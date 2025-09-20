package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goliatone/go-router"
)

var (
	ErrTokenMismatch    = errors.New("CSRF token mismatch")
	ErrTokenMissing     = errors.New("CSRF token missing")
	ErrTokenExpired     = errors.New("CSRF token expired")
	ErrSecureKeyMissing = errors.New("CSRF secure key required for stateless mode")
)

// DefaultTokenLength is the default length for CSRF tokens
const DefaultTokenLength = 32

// DefaultContextKey is the default key for storing CSRF tokens in context
const DefaultContextKey = "csrf_token"

// DefaultFormFieldName is the default name for the CSRF token form field
const DefaultFormFieldName = "_token"

// DefaultHeaderName is the default header name for CSRF tokens
const DefaultHeaderName = "X-CSRF-Token"

// Config defines the configuration for CSRF middleware
type Config struct {
	// Skip defines a function to skip middleware
	Skip func(router.Context) bool

	// TokenLength defines the length of the generated token
	TokenLength int

	// ContextKey defines the key for storing the token in context
	ContextKey string

	// FormFieldName defines the name of the form field containing the token
	FormFieldName string

	// HeaderName defines the header name for the token
	HeaderName string

	// TokenLookup defines where to look for the token
	// Format: "form:_token,header:X-CSRF-Token"
	TokenLookup string

	// Storage defines how tokens are stored and retrieved
	// If nil, tokens are generated per request (stateless)
	Storage Storage

	// ErrorHandler defines the error handler
	ErrorHandler router.ErrorHandler

	// SuccessHandler defines the success handler
	SuccessHandler router.HandlerFunc

	// SafeMethods defines HTTP methods that don't require CSRF protection
	SafeMethods []string

	// Expiration defines how long tokens are valid (only used with Storage)
	Expiration time.Duration

	// SecureKey is used for token generation when using stateless mode
	SecureKey []byte
}

// Storage interface for storing and retrieving CSRF tokens
type Storage interface {
	Get(key string) (string, error)
	Set(key string, value string, expiration time.Duration) error
	Delete(key string) error
}

// TokenExtractor defines a function to extract token from request
type TokenExtractor func(router.Context) (string, error)

// New creates a new CSRF middleware
func New(config ...Config) router.MiddlewareFunc {
	return func(hf router.HandlerFunc) router.HandlerFunc {
		cfg := configDefault(config...)

		return func(ctx router.Context) error {
			if cfg.Skip != nil && cfg.Skip(ctx) {
				return ctx.Next()
			}

			token, err := getOrGenerateToken(ctx, cfg)
			if err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			ctx.Locals(cfg.ContextKey, token)
			ctx.Locals(cfg.ContextKey+"_field", cfg.FormFieldName)
			ctx.Locals(cfg.ContextKey+"_header", cfg.HeaderName)

			// safe methods don't require validation
			method := strings.ToUpper(ctx.Method())
			if slices.Contains(cfg.SafeMethods, method) {
				return cfg.SuccessHandler(ctx)
			}

			if err := validateToken(ctx, cfg, token); err != nil {
				return cfg.ErrorHandler(ctx, err)
			}

			return cfg.SuccessHandler(ctx)
		}
	}
}

// getOrGenerateToken generates or retrieves a CSRF token
func getOrGenerateToken(ctx router.Context, cfg Config) (string, error) {
	if cfg.Storage != nil {
		// storage based mode, we check if token exists for this session/user
		sessionKey := getSessionKey(ctx)
		if token, err := cfg.Storage.Get(sessionKey); err == nil && token != "" {
			return token, nil
		}

		// we generate new token and store it
		token, err := generateToken(cfg.TokenLength)
		if err != nil {
			return "", err
		}

		if err := cfg.Storage.Set(sessionKey, token, cfg.Expiration); err != nil {
			return "", err
		}

		return token, nil
	}

	return generateStatelessToken(ctx, cfg)
}

// validateToken validates the CSRF token from the request
func validateToken(ctx router.Context, cfg Config, expectedToken string) error {
	receivedToken, err := extractToken(ctx, cfg)
	if err != nil {
		return err
	}

	if receivedToken == "" {
		return ErrTokenMissing
	}

	if cfg.Storage != nil {
		if expectedToken == "" {
			return ErrTokenMismatch
		}
		if subtle.ConstantTimeCompare([]byte(receivedToken), []byte(expectedToken)) != 1 {
			return ErrTokenMismatch
		}
		return nil
	}

	return validateStatelessToken(ctx, cfg, receivedToken)
}

// generateToken generates a cryptographically secure random token
func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateStatelessToken(ctx router.Context, cfg Config) (string, error) {
	if len(cfg.SecureKey) == 0 {
		return "", ErrSecureKeyMissing
	}

	nonce := make([]byte, cfg.TokenLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	sessionKey := getSessionKey(ctx)
	timestamp := time.Now().UTC().Unix()
	payload := fmt.Sprintf("%d:%s:%s", timestamp, hex.EncodeToString(nonce), sessionKey)

	mac := hmac.New(sha256.New, cfg.SecureKey)
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	token := fmt.Sprintf("%s:%s", payload, hex.EncodeToString(signature))
	return base64.RawURLEncoding.EncodeToString([]byte(token)), nil
}

func validateStatelessToken(ctx router.Context, cfg Config, token string) error {
	if len(cfg.SecureKey) == 0 {
		return ErrSecureKeyMissing
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrTokenMismatch
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 4 {
		return ErrTokenMismatch
	}

	timestampStr, nonceHex, sessionFromToken, signatureHex := parts[0], parts[1], parts[2], parts[3]

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return ErrTokenMismatch
	}

	if _, err := hex.DecodeString(nonceHex); err != nil {
		return ErrTokenMismatch
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return ErrTokenMismatch
	}

	payload := strings.Join(parts[:3], ":")
	mac := hmac.New(sha256.New, cfg.SecureKey)
	mac.Write([]byte(payload))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSignature) {
		return ErrTokenMismatch
	}

	if subtle.ConstantTimeCompare([]byte(sessionFromToken), []byte(getSessionKey(ctx))) != 1 {
		return ErrTokenMismatch
	}

	if cfg.Expiration > 0 {
		expiresAt := time.Unix(timestamp, 0).Add(cfg.Expiration)
		if time.Now().UTC().After(expiresAt) {
			return ErrTokenExpired
		}
	}

	return nil
}

func extractToken(ctx router.Context, cfg Config) (string, error) {
	extractors := getExtractors(cfg.TokenLookup, cfg.FormFieldName, cfg.HeaderName)

	for _, extractor := range extractors {
		token, err := extractor(ctx)
		if token != "" && err == nil {
			return token, nil
		}
	}

	return "", nil
}

// getSessionKey generates a session key for token storage
func getSessionKey(ctx router.Context) string {
	// Try to get session ID or user ID for storage key
	if sessionID := ctx.Locals("session_id"); sessionID != nil {
		if id, ok := sessionID.(string); ok && id != "" {
			return "csrf_" + id
		}
	}

	if userID := ctx.Locals("user_id"); userID != nil {
		if id, ok := userID.(string); ok && id != "" {
			return "csrf_user_" + id
		}
	}

	// fallback to IP based key, less secure but OK
	return "csrf_ip_" + ctx.IP()
}

// getExtractors returns token extractors based on configuration
func getExtractors(tokenLookup, formField, header string) []TokenExtractor {
	var extractors []TokenExtractor

	if tokenLookup == "" {
		// Default extractors
		extractors = append(extractors,
			extractorFromForm(formField),
			extractorFromHeader(header),
		)
		return extractors
	}

	// Parse tokenLookup: "form:_token,header:X-CSRF-Token"
	parts := strings.Split(tokenLookup, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "form:") {
			field := strings.TrimPrefix(part, "form:")
			extractors = append(extractors, extractorFromForm(field))
		} else if strings.HasPrefix(part, "header:") {
			headerName := strings.TrimPrefix(part, "header:")
			extractors = append(extractors, extractorFromHeader(headerName))
		}
	}

	return extractors
}

// extractorFromForm extracts token from form data
func extractorFromForm(fieldName string) TokenExtractor {
	return func(ctx router.Context) (string, error) {
		return ctx.FormValue(fieldName), nil
	}
}

// extractorFromHeader extracts token from request header
func extractorFromHeader(headerName string) TokenExtractor {
	return func(ctx router.Context) (string, error) {
		return ctx.GetString(headerName, ""), nil
	}
}

// configDefault returns a default config
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		base := Config{
			TokenLength:   DefaultTokenLength,
			ContextKey:    DefaultContextKey,
			FormFieldName: DefaultFormFieldName,
			HeaderName:    DefaultHeaderName,
			SafeMethods:   []string{"GET", "HEAD", "OPTIONS", "TRACE"},
			Expiration:    24 * time.Hour,
			SuccessHandler: func(ctx router.Context) error {
				return ctx.Next()
			},
		}

		base.ErrorHandler = defaultErrorHandler(base)
		base.SecureKey = initializeSecureKey(base.SecureKey, base.Storage)
		return base
	}

	cfg := config[0]

	if cfg.TokenLength == 0 {
		cfg.TokenLength = DefaultTokenLength
	}

	if cfg.ContextKey == "" {
		cfg.ContextKey = DefaultContextKey
	}

	if cfg.FormFieldName == "" {
		cfg.FormFieldName = DefaultFormFieldName
	}

	if cfg.HeaderName == "" {
		cfg.HeaderName = DefaultHeaderName
	}

	if cfg.SafeMethods == nil {
		cfg.SafeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	}

	if cfg.Expiration == 0 {
		cfg.Expiration = 24 * time.Hour
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler(cfg)
	}

	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(ctx router.Context) error {
			return ctx.Next()
		}
	}

	cfg.SecureKey = initializeSecureKey(cfg.SecureKey, cfg.Storage)

	return cfg
}

func defaultErrorHandler(cfg Config) router.ErrorHandler {
	return func(ctx router.Context, err error) error {
		switch err {
		case ErrTokenMissing:
			return ctx.Status(router.StatusBadRequest).SendString("CSRF token missing")
		case ErrTokenMismatch:
			return ctx.Status(router.StatusForbidden).SendString("CSRF token mismatch")
		case ErrTokenExpired:
			return ctx.Status(router.StatusForbidden).SendString("CSRF token expired")
		case ErrSecureKeyMissing:
			return ctx.Status(router.StatusInternalServerError).SendString("CSRF configuration error")
		default:
			return ctx.Status(router.StatusInternalServerError).SendString("CSRF validation error")
		}
	}
}

func initializeSecureKey(current []byte, storage Storage) []byte {
	if storage != nil {
		return current
	}
	if len(current) > 0 {
		if len(current) < 32 {
			panic(fmt.Errorf("csrf: secure key must be at least 32 bytes, got %d", len(current)))
		}
		return current
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Errorf("csrf: unable to initialize secure key: %w", err))
	}
	return key
}

// CSRFTemplateHelpers returns template helper functions for CSRF protection
func CSRFTemplateHelpers() map[string]any {
	return map[string]any{
		"csrf_token":       csrfToken,
		"csrf_field":       csrfField,
		"csrf_meta":        csrfMeta,
		"csrf_header_name": csrfHeaderName,
	}
}

// CSRFTemplateHelpersWithRouter returns template helpers with access to router context
func CSRFTemplateHelpersWithRouter(ctx router.Context, tokenKey string) map[string]any {
	if tokenKey == "" {
		tokenKey = DefaultContextKey
	}

	helpers := CSRFTemplateHelpers()

	fieldName := DefaultFormFieldName
	if raw := ctx.Locals(tokenKey + "_field"); raw != nil {
		if val, ok := raw.(string); ok && val != "" {
			fieldName = val
		}
	}

	headerName := DefaultHeaderName
	if raw := ctx.Locals(tokenKey + "_header"); raw != nil {
		if val, ok := raw.(string); ok && val != "" {
			headerName = val
		}
	}

	// Override functions to use the actual token from context
	if token := ctx.Locals(tokenKey); token != nil {
		if tokenStr, ok := token.(string); ok {
			helpers["csrf_token"] = func() string { return tokenStr }
			helpers["csrf_field"] = func() template.HTML {
				return template.HTML(`<input type="hidden" name="` + fieldName + `" value="` + tokenStr + `">`)
			}
			helpers["csrf_meta"] = func() template.HTML {
				return template.HTML(`<meta name="csrf-token" content="` + tokenStr + `">`)
			}
		}
	}

	helpers["csrf_header_name"] = func() string { return headerName }

	return helpers
}

// Template helper functions

// csrfToken returns the CSRF token (placeholder - requires context integration)
func csrfToken() string {
	return "{{ .csrf_token }}"
}

// csrfField returns an HTML hidden input field with the CSRF token
func csrfField() template.HTML {
	return template.HTML(`<input type="hidden" name="` + DefaultFormFieldName + `" value="{{ .csrf_token }}">`)
}

// csrfMeta returns an HTML meta tag with the CSRF token
func csrfMeta() template.HTML {
	return template.HTML(`<meta name="csrf-token" content="{{ .csrf_token }}">`)
}

// csrfHeaderName returns the default CSRF header name
func csrfHeaderName() string {
	return DefaultHeaderName
}
