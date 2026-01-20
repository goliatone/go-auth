package auth0example

import (
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/auth0"
	"github.com/goliatone/go-auth/repository"
	"github.com/uptrace/bun"
)

// MinimalConfig holds the configuration needed for Auth0 token validation.
type MinimalConfig struct {
	Auth              auth.Config
	Domain            string
	Audience          []string
	Namespace         string
	AcceptLocalTokens bool
}

// ExampleMinimalSetup wires Auth0 JWT validation into an authenticator.
func ExampleMinimalSetup(db *bun.DB, cfg MinimalConfig) (*auth.Auther, *auth.RouteAuthenticator, *auth0.TokenValidator, error) {
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
		return nil, nil, nil, err
	}

	if cfg.AcceptLocalTokens {
		composite := auth.NewMultiTokenValidator(validator, authenticator.TokenService())
		authenticator = authenticator.WithTokenValidator(composite)
	} else {
		authenticator = authenticator.WithTokenValidator(validator)
	}

	httpAuth, err := auth.NewHTTPAuthenticator(authenticator, cfg.Auth)
	if err != nil {
		return nil, nil, nil, err
	}

	return authenticator, httpAuth, validator, nil
}
