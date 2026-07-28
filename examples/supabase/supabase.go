package supabaseexample

import (
	"context"
	"net/http"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/goliatone/go-auth/provider/supabase"
)

// RuntimeConfig contains values loaded by the host from configuration and its
// secret manager. Secret values must never originate in browser input.
type RuntimeConfig struct {
	ProjectURL                string
	ClientID                  string
	ClientSecret              auth.Secret
	CallbackURL               string
	AdminCredential           auth.Secret
	PublishableKey            auth.Secret
	AuthorizationProofKey     auth.Secret
	Environment               string
	ProviderSessionDeployment auth.ProviderSessionDeployment
	AuthorizationUIURL        string
	ReturnURLs                []string
	IDTokenAudience           []string
	AccessAudience            []string
	OAuthClients              map[string]supabase.AuthorizationClientPolicy
}

type Services struct {
	OIDC          oidc.ProviderConfig
	Principal     oidc.PrincipalMapper
	Admin         *supabase.AdminClient
	Sessions      *supabase.SessionClient
	Authorization *supabase.AuthorizationService
}

// Build constructs the Supabase service boundaries. The host supplies the
// provider-session token reader, validated-token implementation, CSRF
// verifier, and HTTP client.
func Build(
	config RuntimeConfig,
	userTokens auth.UserTokenProvider,
	validator supabase.RefreshTokenValidator,
	csrf supabase.AuthorizationCSRFVerifier,
	httpClient *http.Client,
) (Services, error) {
	providerConfig := supabase.Config{
		ProjectURL:                config.ProjectURL,
		ClientID:                  config.ClientID,
		ClientSecret:              config.ClientSecret,
		TokenEndpointAuthMethod:   oidc.TokenEndpointAuthClientSecretBasic,
		CallbackURL:               config.CallbackURL,
		IDTokenAudience:           config.IDTokenAudience,
		AccessTokenAudience:       config.AccessAudience,
		AuthorizationUIURL:        config.AuthorizationUIURL,
		AllowedReturnURLs:         config.ReturnURLs,
		AdminCredential:           config.AdminCredential,
		PublishableKey:            config.PublishableKey,
		Environment:               config.Environment,
		ProviderSessionDeployment: config.ProviderSessionDeployment,
	}.WithDefaults()
	oidcConfig, err := providerConfig.OIDCConfig()
	if err != nil {
		return Services{}, err
	}
	principal, err := providerConfig.PrincipalMapper("department")
	if err != nil {
		return Services{}, err
	}
	client, err := supabase.NewClient(providerConfig, userTokens, httpClient)
	if err != nil {
		return Services{}, err
	}
	admin, err := supabase.NewHardenedAdminClient(client)
	if err != nil {
		return Services{}, err
	}
	sessions, err := supabase.NewSessionClient(client, validator)
	if err != nil {
		return Services{}, err
	}
	authorization, err := supabase.NewAuthorizationService(supabase.AuthorizationServiceConfig{
		Client: client, Clients: config.OAuthClients, CSRFVerifier: csrf,
		DecisionProofKey: config.AuthorizationProofKey,
	})
	if err != nil {
		return Services{}, err
	}
	return Services{
		OIDC: oidcConfig, Principal: principal, Admin: admin,
		Sessions: sessions, Authorization: authorization,
	}, nil
}

// WireProviderSessions assigns Supabase only to provider remote work. The
// manager continues to own locking, encryption, persistence, and local
// revocation.
func WireProviderSessions(
	base auth.ProviderSessionManagerConfig,
	sessions *supabase.SessionClient,
) auth.ProviderSessionManagerConfig {
	base.Refresher = sessions
	base.Reconciler = sessions
	base.RevocationHook = sessions
	return base
}

// NewLifecycleCoordinator wires local-only session invalidation, durable
// operation authority, and freshness delivery. The supplied store must be
// Postgres-backed. Security-restricting operations use this coordinator instead
// of calling Admin directly.
func NewLifecycleCoordinator(
	local auth.ProviderSessionLocalInvalidator,
	freshness auth.LifecycleFreshnessInvalidator,
	store auth.LifecycleOperationStore,
) (*auth.LifecycleCoordinator, error) {
	lifecycle, _ := local.(auth.ProviderSessionLifecycleInvalidator)
	return auth.NewLifecycleCoordinator(auth.LifecycleCoordinatorConfig{
		LocalInvalidator:     local,
		LifecycleInvalidator: lifecycle,
		Freshness:            freshness,
		OperationStore:       store,
		RequireDurable:       true,
		RequirePermits:       true,
		ResultTTL:            24 * time.Hour,
	})
}

func Suspend(
	ctx context.Context,
	coordinator *auth.LifecycleCoordinator,
	admin *supabase.AdminClient,
	request auth.AccountLifecycleRequest,
) (auth.LifecycleCoordinationResult, error) {
	return coordinator.Coordinate(ctx, auth.LifecycleCoordinationRequest{
		Operation: request.Operation,
		Remote:    admin.SuspendExecutor(request),
	})
}

func RemoveFactor(
	ctx context.Context,
	coordinator *auth.LifecycleCoordinator,
	admin *supabase.AdminClient,
	request auth.FactorRemoveRequest,
) (auth.LifecycleCoordinationResult, error) {
	// Factor state is re-read authoritatively by the provider adapter. Revoke
	// conservatively before that read so a stale caller hint can never bypass
	// local-first ordering if the target factor is verified.
	return coordinator.Coordinate(ctx, auth.LifecycleCoordinationRequest{
		Operation: request.Operation,
		Remote:    admin.RemoveFactorExecutor(request),
	})
}
