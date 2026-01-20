package extensions

import (
	"encoding/base64"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/repository"
	"github.com/goliatone/go-auth/social"
	"github.com/goliatone/go-auth/social/providers/github"
	"github.com/goliatone/go-auth/social/providers/google"
	"github.com/goliatone/go-router"
	"github.com/uptrace/bun"
)

// SocialExampleConfig holds the minimal configuration for the example wiring.
type SocialExampleConfig struct {
	BaseURL            string
	Auth               auth.Config
	StateEncryptionKey string
	StateHMACKey       string
	GitHubClientID     string
	GitHubClientSecret string
	GoogleClientID     string
	GoogleClientSecret string
}

// ExampleSocialLoginSetup wires local auth with social login and HTTP routes.
func ExampleSocialLoginSetup(db *bun.DB, group router.Group, cfg SocialExampleConfig) (*auth.Auther, *social.SocialAuthenticator, *social.HTTPController) {
	repoManager := repository.NewRepositoryManager(db)
	userRepo := repoManager.Users()
	socialRepo := repository.NewSocialAccountRepository(db)

	localProvider := auth.NewUserProvider(userRepo)
	authenticator := auth.NewAuthenticator(localProvider, cfg.Auth)

	stateEncKey, _ := base64.StdEncoding.DecodeString(cfg.StateEncryptionKey)
	stateHMACKey, _ := base64.StdEncoding.DecodeString(cfg.StateHMACKey)

	socialAuth := social.NewSocialAuthenticator(
		socialRepo,
		userRepo,
		authenticator.TokenService(),
		social.SocialAuthConfig{
			DefaultRedirectURL:   "/",
			StateEncryptionKey:   stateEncKey,
			StateHMACKey:         stateHMACKey,
			AllowSignup:          true,
			AllowLinking:         true,
			RequireEmailVerified: true,
		},
		social.WithLinkingPolicy(social.PolicyEmailMatch()),
		social.WithProvider(github.New(github.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			CallbackURL:  cfg.BaseURL + "/auth/social/github/callback",
		})),
		social.WithProvider(google.New(google.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			CallbackURL:  cfg.BaseURL + "/auth/social/google/callback",
		})),
	)

	controller := social.NewHTTPController(socialAuth, social.HTTPConfig{
		PathPrefix:        "/auth/social",
		SessionContextKey: cfg.Auth.GetContextKey(),
		CookieName:        cfg.Auth.GetContextKey(),
		SuccessRedirect:   "/dashboard",
		ErrorRedirect:     "/login?error=auth_failed",
		CookieSecure:      true,
		CookieHTTPOnly:    true,
		CookieSameSite:    "Lax",
	})
	controller.RegisterRoutes(group)

	return authenticator, socialAuth, controller
}
