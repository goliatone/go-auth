package supabase

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
	"github.com/stretchr/testify/require"
)

func validSupabaseClaims(now time.Time) (
	auth.ValidatedTokenContext,
	auth.ValidatedTokenContext,
	jwt.MapClaims,
	jwt.MapClaims,
) {
	subject := "5f090ad0-09fb-49e0-884d-a4453d1a7c33"
	id := auth.ValidatedTokenContext{
		Issuer:           "https://project.supabase.co/auth/v1",
		Subject:          subject,
		Audiences:        []string{"client-1"},
		SessionID:        "session-1",
		ClientID:         "client-1",
		AssuranceLevel:   "aal1",
		AssuranceMethods: []string{"password"},
		AuthenticationAt: now.Add(-time.Minute),
		IssuedAt:         now.Add(-time.Minute),
		ExpiresAt:        now.Add(time.Hour),
	}
	access := id.Clone()
	access.Audiences = []string{"authenticated"}
	return id, access,
		jwt.MapClaims{
			"sub":            subject,
			"role":           "authenticated",
			"email":          "user@example.com",
			"email_verified": true,
		},
		jwt.MapClaims{
			"sub":  subject,
			"role": "authenticated",
			"app_metadata": map[string]any{
				"department":  "field",
				"permissions": []any{"admin"},
			},
			"user_metadata": map[string]any{
				"permissions": []any{"admin"},
				"aal":         "aal2",
			},
		}
}

func TestClaimsMapperNormalizesSupabaseSecurityContext(t *testing.T) {
	now := time.Now().UTC()
	id, access, idClaims, accessClaims := validSupabaseClaims(now)
	mapper := ClaimsMapper{AllowedHookClaims: []string{"department"}}
	identity, err := mapper.MapPrincipal(context.Background(), oidc.ProviderConfig{
		Key: ProviderKey, ClientID: "client-1",
	}, id, &access, idClaims, accessClaims, nil)
	require.NoError(t, err)
	require.Equal(t, id.Subject, identity.Subject)
	require.Equal(t, "session-1", identity.ProviderSessionID)
	require.Equal(t, "aal1", identity.AssuranceLevel)
	require.Equal(t, []string{"password"}, identity.AssuranceMethods)
	require.Equal(t, "authenticated", identity.Metadata["provider_role"])
	require.Equal(t, "field", identity.Metadata["hook.department"])
	require.NotContains(t, identity.Metadata, "permissions")
	require.NotContains(t, identity.Metadata, "aal")
	require.Equal(t, oidc.ClaimSourceAccessToken, identity.Provenance["provider_role"])
}

func TestClaimsMapperRejectsInvalidOrConflictingClaims(t *testing.T) {
	now := time.Now().UTC()
	tests := map[string]func(*auth.ValidatedTokenContext, *auth.ValidatedTokenContext, jwt.MapClaims, jwt.MapClaims){
		"subject": func(id, _ *auth.ValidatedTokenContext, idClaims, _ jwt.MapClaims) {
			id.Subject = "not-a-uuid"
			idClaims["sub"] = "not-a-uuid"
		},
		"session": func(id, access *auth.ValidatedTokenContext, _, _ jwt.MapClaims) {
			id.SessionID, access.SessionID = "", ""
		},
		"assurance": func(id, access *auth.ValidatedTokenContext, _, _ jwt.MapClaims) {
			id.AssuranceLevel, access.AssuranceLevel = "aal3", "aal3"
		},
		"methods": func(id, access *auth.ValidatedTokenContext, _, _ jwt.MapClaims) {
			id.AssuranceMethods, access.AssuranceMethods = nil, nil
		},
		"role conflict": func(_ *auth.ValidatedTokenContext, _ *auth.ValidatedTokenContext, idClaims, _ jwt.MapClaims) {
			idClaims["role"] = "service_role"
		},
		"service role": func(_ *auth.ValidatedTokenContext, _ *auth.ValidatedTokenContext, idClaims, accessClaims jwt.MapClaims) {
			idClaims["role"], accessClaims["role"] = "service_role", "service_role"
		},
		"auth time conflict": func(_ *auth.ValidatedTokenContext, access *auth.ValidatedTokenContext, _, _ jwt.MapClaims) {
			access.AuthenticationAt = access.AuthenticationAt.Add(time.Second)
		},
		"expiry": func(id, _ *auth.ValidatedTokenContext, _, _ jwt.MapClaims) {
			id.ExpiresAt = id.IssuedAt
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			id, access, idClaims, accessClaims := validSupabaseClaims(now)
			mutate(&id, &access, idClaims, accessClaims)
			_, err := (ClaimsMapper{}).MapPrincipal(
				context.Background(),
				oidc.ProviderConfig{Key: ProviderKey, ClientID: "client-1"},
				id, &access, idClaims, accessClaims, nil,
			)
			require.Error(t, err)
		})
	}
}

func TestClaimsMapperAlwaysRejectsPrivilegedRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{
		"anon", "service_role", "supabase_admin", "postgres", "authenticator", "dashboard_user",
	} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			now := time.Now().UTC()
			id, access, idClaims, accessClaims := validSupabaseClaims(now)
			idClaims["role"], accessClaims["role"] = role, role
			_, err := (ClaimsMapper{AllowedUserRoles: []string{role}}).MapPrincipal(
				context.Background(),
				oidc.ProviderConfig{Key: ProviderKey, ClientID: "client-1"},
				id, &access, idClaims, accessClaims, nil,
			)
			require.ErrorIs(t, err, auth.ErrUnableToMapClaims)
		})
	}
}

func TestClaimsMapperRequiresAccessTokenAndSafeHookAllowlist(t *testing.T) {
	now := time.Now().UTC()
	id, _, idClaims, accessClaims := validSupabaseClaims(now)
	_, err := (ClaimsMapper{}).MapPrincipal(
		context.Background(),
		oidc.ProviderConfig{Key: ProviderKey, ClientID: "client-1"},
		id, nil, idClaims, accessClaims, nil,
	)
	require.Error(t, err)

	_, err = validConfig().PrincipalMapper("permissions")
	require.ErrorIs(t, err, ErrInvalidConfig)
}
