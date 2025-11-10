package jwtware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-router"
)

var (
	defaultTokenLookup       = "header:" + router.HeaderAuthorization
	ErrJWTMissingOrMalformed = errors.New("missing or malformed JWT")
)

// TokenValidator interface for validating tokens without import cycles
// This mirrors the TokenService.Validate method from the auth package
type TokenValidator interface {
	Validate(tokenString string) (AuthClaims, error)
}

// AuthClaims interface for structured claims without import cycles
// This mirrors the AuthClaims interface from the auth package
type AuthClaims interface {
	Subject() string
	UserID() string
	Role() string
	CanRead(resource string) bool
	CanEdit(resource string) bool
	CanCreate(resource string) bool
	CanDelete(resource string) bool
	HasRole(role string) bool
	IsAtLeast(minRole string) bool
}

// ValidationListener is invoked after a token has been validated but before authorization checks.
type ValidationListener func(ctx router.Context, claims AuthClaims) error

type Config struct {
	Filter              func(router.Context) bool
	SuccessHandler      router.HandlerFunc
	ErrorHandler        router.ErrorHandler
	SigningKey          SigningKey
	SigningKeys         map[string]SigningKey
	ContextKey          string
	TokenLookup         string
	AuthScheme          string
	KeyFunc             jwt.Keyfunc
	JWKSetURLs          []string
	LocalTokenSerilizer func(*jwt.Token) any
	// TokenValidator is required for token validation
	TokenValidator TokenValidator

	// Optional RBAC fields for enhanced middleware functionality
	// RoleChecker is an optional function to validate roles against custom logic
	RoleChecker func(AuthClaims, string) bool
	// RequiredRole specifies an exact role that must be present
	RequiredRole string
	// MinimumRole specifies the minimum role level required (uses role hierarchy)
	MinimumRole string

	// ContextEnricher is an optional function to propagate claims to the standard
	// Go context. If provided, it will be called after successful token validation.
	ContextEnricher func(c context.Context, claims AuthClaims) context.Context

	// ValidationListeners are invoked after token validation succeeds. Use them to
	// emit events, update schema caches, or perform bookkeeping before the request proceeds.
	ValidationListeners []ValidationListener

	// Template integration fields for automatic user context registration
	// TemplateUserKey specifies the key for storing user data for templates in router context.
	// If set, the middleware will automatically store user data under this key for template usage.
	TemplateUserKey string
	// UserProvider is an optional function to convert AuthClaims to a User object for templates.
	// If not provided, the AuthClaims will be stored directly under TemplateUserKey.
	UserProvider func(AuthClaims) (any, error)
}

type SigningKey struct {
	JWTAlg string
	Key    any
}

func New(config ...Config) router.MiddlewareFunc {
	return func(hf router.HandlerFunc) router.HandlerFunc {
		cfg := GetDefaultConfig(config...)
		return func(ctx router.Context) error {
			if cfg.Filter != nil && cfg.Filter(ctx) {
				return ctx.Next()
			}

			a, err := ExtractRawTokenFromContext(ctx, cfg.getExtractors())
			if err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			claims, err := cfg.TokenValidator.Validate(a)
			if err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			if err := cfg.runValidationListeners(ctx, claims); err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			if err := performAuthorizationChecks(claims, cfg); err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			ctx.Locals(cfg.ContextKey, claims)

			// Store user data for template usage if configured
			if cfg.TemplateUserKey != "" {
				var templateUser any
				if cfg.UserProvider != nil {
					// Try to get full user object using the provider
					user, err := cfg.UserProvider(claims)
					if err != nil {
						// Log error but don't fail - use claims instead
						// TODO: Consider adding logging interface to Config for better error reporting
						templateUser = claims
					} else {
						templateUser = user
					}
				} else {
					// Use claims directly as template user data
					templateUser = claims
				}

				// Use LocalsMerge if templateUser is a map[string]any, otherwise use Locals
				if userMap, ok := templateUser.(map[string]any); ok {
					ctx.LocalsMerge(cfg.TemplateUserKey, userMap)
				} else {
					ctx.Locals(cfg.TemplateUserKey, templateUser)
				}
			}

			// if a context enricher we use it to propagate claims to the standard context
			if cfg.ContextEnricher != nil {
				stdCtx := ctx.Context()
				stdCtxWithClaims := cfg.ContextEnricher(stdCtx, claims)
				ctx.SetContext(stdCtxWithClaims)
			}

			return cfg.SuccessHandler(ctx)
		}
	}
}

// performAuthorizationChecks performs RBAC authorization checks using the configured options
func performAuthorizationChecks(claims AuthClaims, cfg Config) error {
	// If no RBAC configuration is provided, skip authorization checks
	if cfg.RequiredRole == "" && cfg.MinimumRole == "" && cfg.RoleChecker == nil {
		return nil
	}

	if cfg.RequiredRole != "" {
		if !claims.HasRole(cfg.RequiredRole) {
			return fmt.Errorf("access denied: required role '%s' not found", cfg.RequiredRole)
		}
	}

	// user has at least the minimum role level?
	if cfg.MinimumRole != "" {
		if !claims.IsAtLeast(cfg.MinimumRole) {
			return fmt.Errorf("access denied: minimum role '%s' required", cfg.MinimumRole)
		}
	}

	// use custom role checker if provided
	if cfg.RoleChecker != nil {
		// RoleChecker can check against either RequiredRole or MinimumRole
		roleToCheck := cfg.RequiredRole
		if roleToCheck == "" {
			roleToCheck = cfg.MinimumRole
		}

		if roleToCheck != "" && !cfg.RoleChecker(claims, roleToCheck) {
			return fmt.Errorf("access denied: custom role check failed for role '%s'", roleToCheck)
		}
	}

	return nil
}

func ExtractRawTokenFromContext(ctx router.Context, extractors []JWTExtractor) (string, error) {
	var raw string
	var err error

	for _, extractor := range extractors {
		raw, err = extractor(ctx)
		if raw != "" && err == nil {
			break
		}
	}

	return raw, err
}

func GetDefaultConfig(config ...Config) (cfg Config) {
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(ctx router.Context) error {
			return ctx.Next()
		}
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c router.Context, err error) error {
			if err.Error() == ErrJWTMissingOrMalformed.Error() {
				return c.Status(router.StatusBadRequest).SendString(ErrJWTMissingOrMalformed.Error())
			}
			return c.Status(router.StatusUnauthorized).SendString("Invalid or expired token")
		}
	}

	if cfg.TokenValidator == nil {
		panic("AUTH: JWT middleware configuration: TokenValidator is required.")
	}

	if cfg.SigningKey.Key == nil && len(cfg.SigningKeys) == 0 && len(cfg.JWKSetURLs) == 0 && cfg.KeyFunc == nil {
		panic("AUTH: JWT middleware configuration: At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.")
	}

	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}

	if cfg.TokenLookup == "" {
		cfg.TokenLookup = defaultTokenLookup
	}

	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}

	if cfg.KeyFunc == nil {
		if len(cfg.SigningKeys) > 0 || len(cfg.JWKSetURLs) > 0 {
			var givenKeys map[string]keyfunc.GivenKey
			if cfg.SigningKeys != nil {
				givenKeys = make(map[string]keyfunc.GivenKey, len(cfg.SigningKeys))
				for kid, key := range cfg.SigningKeys {
					givenKeys[kid] = keyfunc.NewGivenCustom(key.Key, keyfunc.GivenKeyOptions{
						Algorithm: key.JWTAlg,
					})
				}
			}
			if len(cfg.JWKSetURLs) > 0 {
				var err error
				cfg.KeyFunc, err = multiKeyfunc(givenKeys, cfg.JWKSetURLs)
				if err != nil {
					panic("Failed to create keyfunc from JWK Set URL: " + err.Error())
				}
			} else {
				cfg.KeyFunc = keyfunc.NewGiven(givenKeys).Keyfunc
			}
		} else {
			cfg.KeyFunc = signingKeyFunc(cfg.SigningKey)
		}
	}

	if cfg.LocalTokenSerilizer == nil {
		cfg.LocalTokenSerilizer = func(t *jwt.Token) any {
			return t
		}
	}

	if cfg.TemplateUserKey == "" {
		cfg.TemplateUserKey = "current_user"
	}

	return cfg
}

func multiKeyfunc(givenKeys map[string]keyfunc.GivenKey, jwtSetUrls []string) (jwt.Keyfunc, error) {
	opts := keyfuncOptions(givenKeys)
	m := make(map[string]keyfunc.Options, len(jwtSetUrls))
	for _, url := range jwtSetUrls {
		m[url] = opts
	}
	mopts := keyfunc.MultipleOptions{
		KeySelector: keyfunc.KeySelectorFirst,
	}
	multi, err := keyfunc.GetMultiple(m, mopts)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT URLs: %w", err)
	}
	return multi.Keyfunc, nil
}

func keyfuncOptions(givenKeys map[string]keyfunc.GivenKey) keyfunc.Options {
	return keyfunc.Options{
		GivenKeys: givenKeys,
		RefreshErrorHandler: func(err error) {
			log.Printf("failed to do a background refresh of JWT set: %s", err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}
}

func (cfg *Config) getExtractors() []JWTExtractor {
	return GetExtractors(cfg.TokenLookup, cfg.AuthScheme)
}

func (cfg *Config) runValidationListeners(ctx router.Context, claims AuthClaims) error {
	for _, listener := range cfg.ValidationListeners {
		if listener == nil {
			continue
		}
		if err := listener(ctx, claims); err != nil {
			return err
		}
	}
	return nil
}

func GetExtractors(tokenLookup string, authSchemes ...string) []JWTExtractor {
	extractors := make([]JWTExtractor, 0)

	authScheme := "Bearer"
	if len(authSchemes) > 0 {
		authScheme = authSchemes[0]
	}

	// header:Authorization,cookie:jwt,query:auth_token,param:token
	rootParts := strings.Split(tokenLookup, ",")
	for _, rootPart := range rootParts {
		//header:Authorization
		parts := strings.Split(strings.TrimSpace(rootPart), ":")

		for i, el := range parts {
			parts[i] = strings.TrimSpace(el)
		}

		switch parts[0] {
		case "header":
			extractors = append(extractors, jwtFromHeader(parts[1], authScheme))
		case "query":
			extractors = append(extractors, jwtFromQuery(parts[1]))
		case "param":
			extractors = append(extractors, jwtFromParam(parts[1]))
		case "cookie":
			extractors = append(extractors, jwtFromCookie(parts[1]))
		}
	}

	return extractors
}

type JWTExtractor func(c router.Context) (string, error)

// jwtFromHeader returns a function that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) func(c router.Context) (string, error) {
	return func(c router.Context) (string, error) {
		a := c.GetString(header, "")
		l := len(authScheme)
		if l == 0 {
			fmt.Println("[WARNING] Missing auth scheme in config definition")
			return "", ErrJWTMissingOrMalformed
		}
		authScheme = strings.TrimSpace(authScheme)
		if len(a) > l+1 && strings.EqualFold(a[:l], authScheme) {
			return strings.TrimSpace(a[l:]), nil
		}
		return "", ErrJWTMissingOrMalformed
	}
}

// jwtFromQuery returns a function that extracts token from the query string.
func jwtFromQuery(param string) func(c router.Context) (string, error) {
	return func(c router.Context) (string, error) {
		token := c.Query(param, "")
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}

// jwtFromParam returns a function that extracts token from the url param string.
func jwtFromParam(param string) func(c router.Context) (string, error) {
	return func(c router.Context) (string, error) {
		token := c.Param(param)
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}

// jwtFromCookie returns a function that extracts token from the named cookie.
func jwtFromCookie(name string) func(c router.Context) (string, error) {
	return func(c router.Context) (string, error) {
		token := c.Cookies(name)
		if token == "" {
			return "", ErrJWTMissingOrMalformed
		}
		return token, nil
	}
}

func signingKeyFunc(key SigningKey) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if key.JWTAlg != "" {
			alg, ok := token.Header["alg"].(string)
			if !ok {
				return nil, fmt.Errorf("unexpected JWT signing method: expected %q got: missing json type", key.JWTAlg)
			}
			if alg != key.JWTAlg {
				return nil, fmt.Errorf("unexpected jwt signing method: expected: %q: got: %q", key.JWTAlg, alg)
			}
		}
		return key.Key, nil
	}
}
