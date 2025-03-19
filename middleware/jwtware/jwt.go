package jwtware

import (
	"errors"
	"fmt"
	"log"
	"reflect"
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

type Config struct {
	Filter              func(router.Context) bool
	SuccessHandler      router.HandlerFunc
	ErrorHandler        router.ErrorHandler
	SigningKey          SigningKey
	SigningKeys         map[string]SigningKey
	ContextKey          string
	Claims              jwt.Claims
	TokenLookup         string
	AuthScheme          string
	KeyFunc             jwt.Keyfunc
	JWKSetURLs          []string
	LocalTokenSerilizer func(*jwt.Token) any
}

type SigningKey struct {
	JWTAlg string
	Key    any
}

func New(config ...Config) router.HandlerFunc {
	cfg := GetDefaultConfig(config...)
	return func(ctx router.Context) error {
		if cfg.Filter != nil && cfg.Filter(ctx) {
			return ctx.Next()
		}

		a, err := ExtractRawTokenFromContext(ctx, cfg.getExtractors())
		if err != nil {
			return cfg.ErrorHandler(ctx, err)
		}

		var t *jwt.Token

		if _, ok := cfg.Claims.(jwt.MapClaims); ok {
			t, err = jwt.Parse(a, cfg.KeyFunc)
		} else {
			ct := reflect.ValueOf(cfg.Claims).Type().Elem()
			claims := reflect.New(ct).Interface().(jwt.Claims)
			t, err = jwt.ParseWithClaims(a, claims, cfg.KeyFunc)
		}

		if err == nil && t.Valid {
			ctx.Locals(cfg.ContextKey, cfg.LocalTokenSerilizer(t))
			return cfg.SuccessHandler(ctx)
		}

		return cfg.ErrorHandler(ctx, err)
	}
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

	if cfg.SigningKey.Key == nil && len(cfg.SigningKeys) == 0 && len(cfg.JWKSetURLs) == 0 && cfg.KeyFunc == nil {
		panic("AUTH: JWT middleware configuration: At least one of the following is required: KeyFunc, JWKSetURLs, SigningKeys, or SigningKey.")
	}

	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}

	if cfg.Claims == nil {
		cfg.Claims = jwt.MapClaims{}
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
