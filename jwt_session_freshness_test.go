package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJWTSessionRechecksPersistedAccount(t *testing.T) {
	db, users, user := upstreamSQLUser(t)
	ctx := context.Background()
	a := auth.NewAuthenticator(auth.NewUserProvider(upstreamTracker{users}), browserTestConfig{})
	token, err := a.Login(ctx, user.Email, "synthetic-password")
	require.NoError(t, err)
	session, err := a.SessionFromToken(token)
	require.NoError(t, err)
	require.Equal(t, user.ID.String(), session.GetUserID())
	for _, tc := range []struct {
		status auth.UserStatus
		err    error
	}{{auth.UserStatusDisabled, auth.ErrUserDisabled}, {auth.UserStatusSuspended, auth.ErrUserSuspended}, {auth.UserStatusArchived, auth.ErrUserArchived}, {auth.UserStatusPending, auth.ErrUserPending}} {
		t.Run(string(tc.status), func(t *testing.T) {
			_, err := users.UpdateStatus(ctx, user.ID, tc.status)
			require.NoError(t, err)
			session, err := a.SessionFromToken(token)
			require.ErrorIs(t, err, tc.err)
			require.Nil(t, session)
			_, err = users.UpdateStatus(ctx, user.ID, auth.UserStatusActive)
			require.NoError(t, err)
			_, err = a.SessionFromToken(token)
			require.NoError(t, err)
		})
	}
	t.Run("deleted", func(t *testing.T) {
		_, err := db.NewDelete().Model((*auth.User)(nil)).Where("id = ?", user.ID).Exec(ctx)
		require.NoError(t, err)
		session, err := a.SessionFromToken(token)
		require.Error(t, err)
		require.Nil(t, session)
	})
}

type jwtFreshnessProvider struct {
	find func(context.Context, string) (auth.Identity, error)
}

func (p jwtFreshnessProvider) VerifyIdentity(c context.Context, id, _ string) (auth.Identity, error) {
	return p.find(c, id)
}
func (p jwtFreshnessProvider) FindIdentityByIdentifier(c context.Context, id string) (auth.Identity, error) {
	return p.find(c, id)
}

func TestJWTSessionProviderFailuresDeny(t *testing.T) {
	cfg := browserTestConfig{}
	identity := TestIdentity{id: uuid.NewString(), role: "member"}
	signer := auth.NewAuthenticator(nil, cfg)
	token, err := signer.TokenService().Generate(identity, nil)
	require.NoError(t, err)
	unavailable := errors.New("identity store unavailable")
	for _, name := range []string{"unavailable", "nil_identity", "typed_nil_identity", "wrong_identity", "invalid_signature"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			provider := jwtFreshnessProvider{find: func(context.Context, string) (auth.Identity, error) {
				calls++
				switch name {
				case "unavailable":
					return nil, unavailable
				case "nil_identity":
					return nil, nil
				case "typed_nil_identity":
					var id *TestIdentity
					return id, nil
				case "wrong_identity":
					return TestIdentity{id: uuid.NewString(), role: "member"}, nil
				}
				return identity, nil
			}}
			a := auth.NewAuthenticator(provider, cfg)
			raw := token
			if name == "invalid_signature" {
				raw += "invalid"
			}
			session, err := a.SessionFromToken(raw)
			require.Error(t, err)
			require.Nil(t, session)
			if name == "unavailable" {
				require.ErrorIs(t, err, unavailable)
			}
			want := 1
			if name == "invalid_signature" {
				want = 0
			}
			require.Equal(t, want, calls)
		})
	}
}

func TestJWTProtectedRouteRechecksPersistedAccount(t *testing.T) {
	_, users, user := upstreamSQLUser(t)
	ctx := context.Background()
	cfg := browserTestConfig{}
	a := auth.NewAuthenticator(auth.NewUserProvider(upstreamTracker{users}), cfg)
	token, err := a.Login(ctx, user.Email, "synthetic-password")
	require.NoError(t, err)
	httpAuth, err := auth.NewHTTPAuthenticator(a, cfg)
	require.NoError(t, err)
	server := router.NewHTTPServer().(*router.HTTPServer)
	calls, listeners := 0, 0
	httpAuth.WithValidationListeners(func(router.Context, jwtware.AuthClaims) error { listeners++; return nil })
	server.Router().Get("/protected", func(c router.Context) error { calls++; return c.SendStatus(http.StatusOK) }, httpAuth.ProtectedRoute(cfg, func(c router.Context, _ error) error { return c.SendStatus(http.StatusUnauthorized) }))
	get := func() int {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		server.WrappedRouter().ServeHTTP(response, req)
		return response.Code
	}
	require.Equal(t, http.StatusOK, get())
	require.Equal(t, 1, calls)
	require.Equal(t, 1, listeners)
	_, err = users.UpdateStatus(ctx, user.ID, auth.UserStatusDisabled)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, get())
	require.Equal(t, 1, calls)
	require.Equal(t, 1, listeners)
	_, err = users.UpdateStatus(ctx, user.ID, auth.UserStatusActive)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, get())
	require.Equal(t, 2, calls)
}

func TestJWTSessionContextAndExternalValidator(t *testing.T) {
	cfg := browserTestConfig{}
	identity := TestIdentity{id: uuid.NewString(), role: "member"}
	signer := auth.NewAuthenticator(nil, cfg)
	token, err := signer.TokenService().Generate(identity, nil)
	require.NoError(t, err)
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request-value")
	calls := 0
	a := auth.NewAuthenticator(jwtFreshnessProvider{find: func(c context.Context, id string) (auth.Identity, error) {
		calls++
		require.Equal(t, "request-value", c.Value(contextKey{}))
		require.Equal(t, identity.ID(), id)
		return identity, nil
	}}, cfg)
	_, err = a.SessionFromTokenContext(ctx, token)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	session, err := a.SessionFromTokenContext(canceled, token)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, session)
	require.Equal(t, 1, calls)
	claims, err := signer.TokenService().Validate(token)
	require.NoError(t, err)
	external := auth.NewAuthenticator(jwtFreshnessProvider{find: func(context.Context, string) (auth.Identity, error) {
		inactive := identity
		inactive.status = auth.UserStatusDisabled
		return inactive, nil
	}}, cfg).
		WithTokenValidator(auth.TokenValidatorFunc(func(string) (auth.AuthClaims, error) { return claims, nil }))
	session, err = external.SessionFromToken("externally-validated-token")
	require.ErrorIs(t, err, auth.ErrUserDisabled)
	require.Nil(t, session)
}

func TestJWTSessionProviderFreeValidation(t *testing.T) {
	cfg := browserTestConfig{}
	signer := auth.NewAuthenticator(nil, cfg)
	token, err := signer.TokenService().Generate(TestIdentity{id: uuid.NewString(), role: "member"}, nil)
	require.NoError(t, err)
	var typedNil *MockIdentityProvider
	for _, provider := range []auth.IdentityProvider{nil, typedNil} {
		a := auth.NewAuthenticator(provider, cfg)
		session, err := a.SessionFromToken(token)
		require.NoError(t, err)
		require.NotNil(t, session)
	}
}
