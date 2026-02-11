package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goliatone/go-logger/glog"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type logCall struct {
	level   string
	message string
	args    []any
}

type captureLogger struct {
	calls []logCall
}

func (l *captureLogger) record(level, message string, args ...any) {
	l.calls = append(l.calls, logCall{level: level, message: message, args: args})
}

func (l *captureLogger) Trace(message string, args ...any) { l.record("trace", message, args...) }
func (l *captureLogger) Debug(message string, args ...any) { l.record("debug", message, args...) }
func (l *captureLogger) Info(message string, args ...any)  { l.record("info", message, args...) }
func (l *captureLogger) Warn(message string, args ...any)  { l.record("warn", message, args...) }
func (l *captureLogger) Error(message string, args ...any) { l.record("error", message, args...) }
func (l *captureLogger) Fatal(message string, args ...any) { l.record("fatal", message, args...) }
func (l *captureLogger) WithContext(context.Context) Logger {
	return l
}

type legacyLoggerSpy struct {
	calls []logCall
}

func (l *legacyLoggerSpy) Debug(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "debug", message: format, args: args})
}
func (l *legacyLoggerSpy) Info(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "info", message: format, args: args})
}
func (l *legacyLoggerSpy) Warn(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "warn", message: format, args: args})
}
func (l *legacyLoggerSpy) Error(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "error", message: format, args: args})
}

type formattedLoggerSpy struct {
	calls []logCall
}

func (l *formattedLoggerSpy) Debugf(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "debug", message: format, args: args})
}
func (l *formattedLoggerSpy) Infof(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "info", message: format, args: args})
}
func (l *formattedLoggerSpy) Warnf(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "warn", message: format, args: args})
}
func (l *formattedLoggerSpy) Errorf(format string, args ...any) {
	l.calls = append(l.calls, logCall{level: "error", message: format, args: args})
}

type loggerProviderSpy struct {
	logger Logger
	byName map[string]Logger
	names  []string
}

func (p *loggerProviderSpy) GetLogger(name string) Logger {
	p.names = append(p.names, name)
	if p.byName != nil {
		if logger, ok := p.byName[name]; ok {
			return logger
		}
	}
	return p.logger
}

type identityProviderStub struct{}

func (identityProviderStub) VerifyIdentity(context.Context, string, string) (Identity, error) {
	return nil, nil
}

func (identityProviderStub) FindIdentityByIdentifier(context.Context, string) (Identity, error) {
	return nil, nil
}

type configStub struct{}

func (configStub) GetSigningKey() string           { return "test-signing-key" }
func (configStub) GetSigningMethod() string        { return "HS256" }
func (configStub) GetContextKey() string           { return "jwt" }
func (configStub) GetTokenExpiration() int         { return 24 }
func (configStub) GetExtendedTokenDuration() int   { return 48 }
func (configStub) GetTokenLookup() string          { return "header:Authorization" }
func (configStub) GetAuthScheme() string           { return "Bearer" }
func (configStub) GetIssuer() string               { return "issuer" }
func (configStub) GetAudience() []string           { return []string{"aud"} }
func (configStub) GetRejectedRouteKey() string     { return "rejected_route" }
func (configStub) GetRejectedRouteDefault() string { return "/login" }

type sessionStub struct {
	userID string
}

func (s sessionStub) GetUserID() string               { return s.userID }
func (s sessionStub) GetUserUUID() (uuid.UUID, error) { return uuid.Nil, nil }
func (s sessionStub) GetAudience() []string           { return nil }
func (s sessionStub) GetIssuer() string               { return "" }
func (s sessionStub) GetIssuedAt() *time.Time         { return nil }
func (s sessionStub) GetData() map[string]any         { return nil }

type identityProviderWithFindError struct {
	err error
}

func (p identityProviderWithFindError) VerifyIdentity(context.Context, string, string) (Identity, error) {
	return nil, nil
}

func (p identityProviderWithFindError) FindIdentityByIdentifier(context.Context, string) (Identity, error) {
	return nil, p.err
}

type authenticatorStub struct {
	loginErr error
}

func (a authenticatorStub) Login(context.Context, string, string) (string, error) {
	return "", a.loginErr
}

func (a authenticatorStub) Impersonate(context.Context, string) (string, error) {
	return "", nil
}

func (a authenticatorStub) SessionFromToken(string) (Session, error) {
	return nil, nil
}

func (a authenticatorStub) IdentityFromSession(context.Context, Session) (Identity, error) {
	return nil, nil
}

func (a authenticatorStub) TokenService() TokenService {
	return nil
}

type loginPayloadStub struct{}

func (loginPayloadStub) GetIdentifier() string    { return "email@example.com" }
func (loginPayloadStub) GetPassword() string      { return "password" }
func (loginPayloadStub) GetExtendedSession() bool { return false }

func TestLoggerContractAliasesAndResolve(t *testing.T) {
	base := defaultLogger()
	require.NotNil(t, base)

	var logger Logger = base
	var provider LoggerProvider = glog.ProviderFromLogger(base)

	resolvedProvider, resolvedLogger := ResolveLogger("auth.test", provider, logger)
	require.NotNil(t, resolvedProvider)
	require.NotNil(t, resolvedLogger)
	require.NotNil(t, resolvedProvider.GetLogger("auth.test"))

	fallback := &captureLogger{}
	providerWithNilLogger := &loggerProviderSpy{byName: map[string]Logger{"auth.test": nil}}
	fallbackProvider, fallbackLogger := ResolveLogger("auth.test", providerWithNilLogger, fallback)
	require.Same(t, fallback, fallbackLogger)
	require.Same(t, fallback, fallbackProvider.GetLogger("auth.test"))
}

func TestFromLegacyLoggerAdapter(t *testing.T) {
	legacy := &legacyLoggerSpy{}
	logger := FromLegacyLogger(legacy)

	logger.Debug("debug %s", "value")
	logger.Info("info %s", "value")
	logger.Warn("warn %s", "value")
	logger.Error("error %s", "value")

	require.Len(t, legacy.calls, 4)
	require.Equal(t, "debug", legacy.calls[0].level)
	require.Equal(t, "debug %s", legacy.calls[0].message)
	require.Equal(t, []any{"value"}, legacy.calls[0].args)
	require.Equal(t, "error", legacy.calls[3].level)

	// Nil legacy logger should resolve to a safe no-op logger.
	FromLegacyLogger(nil).Info("noop")
}

func TestFormattedAdapters(t *testing.T) {
	formatted := &formattedLoggerSpy{}
	logger := FromFormattedLogger(formatted)
	logger.Warn("warn %s", "value")

	require.Len(t, formatted.calls, 1)
	require.Equal(t, "warn", formatted.calls[0].level)
	require.Equal(t, "warn %s", formatted.calls[0].message)
	require.Equal(t, []any{"value"}, formatted.calls[0].args)

	captured := &captureLogger{}
	asFormatted := ToFormattedLogger(captured)
	asFormatted.Errorf("error %d", 42)

	require.Len(t, captured.calls, 1)
	require.Equal(t, "error", captured.calls[0].level)
	require.Equal(t, "error 42", captured.calls[0].message)
}

func TestDefaultLoggerIsAlignedAndSafe(t *testing.T) {
	logger := defaultLogger()
	require.NotNil(t, logger)

	logger.Trace("trace")
	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")
	logger.Fatal("fatal")

	contextual := logger.WithContext(context.Background())
	require.NotNil(t, contextual)
}

func TestAutherWithLoggerProviderResolvesScopedLoggers(t *testing.T) {
	resolved := &captureLogger{}
	provider := &loggerProviderSpy{logger: resolved}

	auther := NewAuthenticator(identityProviderStub{}, configStub{}).
		WithLoggerProvider(provider)

	require.Same(t, resolved, auther.logger)
	require.Contains(t, provider.names, "auth")
	require.Contains(t, provider.names, "auth.token_service")
}

func TestUserProviderWithLoggerProviderResolvesScopedLogger(t *testing.T) {
	resolved := &captureLogger{}
	provider := &loggerProviderSpy{logger: resolved}

	userProvider := NewUserProvider(nil).
		WithLoggerProvider(provider)

	require.Same(t, resolved, userProvider.logger)
	require.Contains(t, provider.names, "auth.user_provider")
}

func TestFinalizePasswordResetHandlerWithLoggerProviderResolvesScopedLogger(t *testing.T) {
	resolved := &captureLogger{}
	provider := &loggerProviderSpy{logger: resolved}

	handler := NewFinalizePasswordResetHandler(nil).
		WithLoggerProvider(provider)

	require.Same(t, resolved, handler.logger)
	require.Contains(t, provider.names, "auth.password_reset")
}

func TestStateMachineWithLoggerProviderResolvesScopedLogger(t *testing.T) {
	resolved := &captureLogger{}
	provider := &loggerProviderSpy{logger: resolved}

	stateMachine := NewUserStateMachine(nil, WithStateMachineLoggerProvider(provider))
	impl, ok := stateMachine.(*userStateMachine)
	require.True(t, ok)
	require.Same(t, resolved, impl.logger)
	require.Contains(t, provider.names, "auth.state_machine")
}

func TestRouteAuthenticatorLoginLogsStructuredError(t *testing.T) {
	expectedErr := errors.New("invalid credentials")
	logger := &captureLogger{}

	httpAuth := &RouteAuthenticator{
		auth:   authenticatorStub{loginErr: expectedErr},
		logger: logger,
	}

	ctx := router.NewMockContext()
	ctx.On("Context").Return(context.Background())

	err := httpAuth.Login(ctx, loginPayloadStub{})
	require.ErrorIs(t, err, expectedErr)

	require.Len(t, logger.calls, 1)
	require.Equal(t, "error", logger.calls[0].level)
	require.Equal(t, "Login error", logger.calls[0].message)
	require.Equal(t, []any{"error", expectedErr}, logger.calls[0].args)
}

func TestAutherIdentityFromSessionLogsStructuredError(t *testing.T) {
	expectedErr := errors.New("identity lookup failed")
	logger := &captureLogger{}

	auther := NewAuthenticator(identityProviderWithFindError{err: expectedErr}, configStub{}).
		WithLoggerProvider(glog.ProviderFromLogger(logger))

	_, err := auther.IdentityFromSession(context.Background(), sessionStub{userID: "user-1"})
	require.ErrorIs(t, err, expectedErr)

	require.Len(t, logger.calls, 1)
	require.Equal(t, "error", logger.calls[0].level)
	require.Equal(t, "IdentityFromSession find identity by identifier", logger.calls[0].message)
	require.Equal(t, []any{"error", expectedErr}, logger.calls[0].args)
}

func TestStateMachineActivitySinkLogsStructuredError(t *testing.T) {
	expectedErr := errors.New("sink unavailable")
	logger := &captureLogger{}

	sm := &userStateMachine{
		logger: logger,
		now:    time.Now,
		activitySink: ActivitySinkFunc(func(context.Context, ActivityEvent) error {
			return expectedErr
		}),
	}

	sm.recordActivity(context.Background(), ActivityEvent{
		EventType: ActivityEventUserStatusChanged,
	})

	require.Len(t, logger.calls, 1)
	require.Equal(t, "warn", logger.calls[0].level)
	require.Equal(t, "state machine activity sink error", logger.calls[0].message)
	require.Equal(t, []any{"error", expectedErr}, logger.calls[0].args)
}

func TestFinalizePasswordResetActivitySinkLogsStructuredError(t *testing.T) {
	expectedErr := errors.New("sink unavailable")
	logger := &captureLogger{}

	userID := uuid.New()
	handler := &FinalizePasswordResetHandler{
		logger: logger,
		activity: ActivitySinkFunc(func(context.Context, ActivityEvent) error {
			return expectedErr
		}),
	}

	handler.recordActivity(context.Background(), &PasswordReset{
		ID:     uuid.New(),
		UserID: &userID,
	})

	require.Len(t, logger.calls, 1)
	require.Equal(t, "warn", logger.calls[0].level)
	require.Equal(t, "activity sink error during password reset", logger.calls[0].message)
	require.Equal(t, []any{"error", expectedErr}, logger.calls[0].args)
}
