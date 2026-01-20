package auth0example

import (
	"context"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/auth0"
	auth0sync "github.com/goliatone/go-auth/provider/auth0/sync"
	"github.com/goliatone/go-auth/repository"
	"github.com/uptrace/bun"
)

// SyncConfig holds the configuration for Auth0 sync wiring.
type SyncConfig struct {
	Auth              auth.Config
	Domain            string
	Audience          []string
	Namespace         string
	AcceptLocalTokens bool
	ManagementDomain  string
	ManagementClientID string
	ManagementSecret   string
}

// ExampleSyncSetup wires Auth0 validation with local user sync helpers.
func ExampleSyncSetup(ctx context.Context, db *bun.DB, cfg SyncConfig) (*auth.Auther, *auth.RouteAuthenticator, *auth0sync.Service, *auth0sync.ManagementClient, error) {
	repoManager := repository.NewRepositoryManager(db)
	userProvider := auth.NewUserProvider(repoManager.Users())

	authenticator := auth.NewAuthenticator(userProvider, cfg.Auth)

	validator, err := auth0.NewTokenValidator(auth0.Config{
		Domain:   cfg.Domain,
		Audience: cfg.Audience,
		ClaimsMapper: &auth0.Auth0ClaimsMapper{
			Namespace: cfg.Namespace,
		},
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if cfg.AcceptLocalTokens {
		composite := auth.NewMultiTokenValidator(validator, authenticator.TokenService())
		authenticator = authenticator.WithTokenValidator(composite)
	} else {
		authenticator = authenticator.WithTokenValidator(validator)
	}

	httpAuth, err := auth.NewHTTPAuthenticator(authenticator, cfg.Auth)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	identifierStore := auth0sync.NewIdentifierStore(db)
	syncService := auth0sync.NewService(auth0sync.Config{
		Users:           repoManager.Users(),
		IdentifierStore: identifierStore,
		Provider:        auth0.IdentifierProviderAuth0,
	})

	managementClient, err := auth0sync.NewManagementClient(ctx, auth0sync.ManagementConfig{
		Domain:       cfg.ManagementDomain,
		ClientID:     cfg.ManagementClientID,
		ClientSecret: cfg.ManagementSecret,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return authenticator, httpAuth, syncService, managementClient, nil
}
