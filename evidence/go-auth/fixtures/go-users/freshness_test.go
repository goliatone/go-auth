package contract_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-users/adapter/goauth"
	"github.com/goliatone/go-users/pkg/types"
	"github.com/goliatone/go-users/registry"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

type selectedScopeKey struct{}

// The host owns scope selection and version storage; assignments use native
// go-users SQL models. Group labels do not populate tenant or organization IDs.
func TestCurrentScopedGrantsWithFreshness(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	raw, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "scoped.db"))
	require.NoError(t, err)
	db := bun.NewDB(raw, sqlitedialect.New())
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	for _, model := range []any{(*auth.User)(nil), (*registry.CustomRole)(nil), (*registry.RoleAssignment)(nil)} {
		_, err = db.NewCreateTable().Model(model).Exec(ctx)
		require.NoError(t, err)
	}
	_, err = db.Exec(`CREATE TABLE host_authorization_versions (user_id TEXT PRIMARY KEY, version INTEGER NOT NULL)`)
	require.NoError(t, err)
	users := auth.NewUsersRepository(db)
	user, err := users.Create(ctx, &auth.User{ID: uuid.New(), Username: "user-a", Email: "user@example.invalid", Role: auth.RoleMember, Status: auth.UserStatusActive})
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO host_authorization_versions VALUES (?,1)`, user.ID)
	require.NoError(t, err)
	reg, err := registry.NewRoleRegistry(registry.RoleRegistryConfig{DB: db})
	require.NoError(t, err)
	role, err := reg.CreateRole(ctx, types.RoleMutation{Name: "reader", Permissions: []string{"resource.read"}, ActorID: user.ID})
	require.NoError(t, err)
	a := types.ScopeFilter{}.WithLabel("group", uuid.New())
	b := types.ScopeFilter{}.WithLabel("group", uuid.New())
	require.NoError(t, reg.AssignRole(ctx, user.ID, role.ID, a, user.ID))
	scoped, err := goauth.NewScopedPermissionsResolver(goauth.ScopedPermissionsResolverConfig{
		RequestResolver: func(c context.Context) (goauth.ScopedPermissionsRequest, error) {
			current, ok := auth.CurrentPermissionsRequestFromContext(c)
			if !ok {
				return goauth.ScopedPermissionsRequest{}, errors.New("missing current authorization state")
			}
			scope, ok := c.Value(selectedScopeKey{}).(types.ScopeFilter)
			if !ok {
				return goauth.ScopedPermissionsRequest{}, errors.New("missing trusted scope")
			}
			return goauth.ScopedPermissionsRequest{Current: current, Scope: scope}, nil
		},
		Cache: auth.CachedPermissionsResolverConfig{Resolver: func(c context.Context) ([]string, error) {
			request, ok := goauth.ScopedPermissionsRequestFromContext(c)
			if !ok {
				return nil, errors.New("missing bound scope")
			}
			subject, err := uuid.Parse(request.Current.Principal.ApplicationSubject())
			if err != nil {
				return nil, err
			}
			assignments, err := reg.ListAssignments(c, types.RoleAssignmentFilter{UserID: subject, Scope: request.Scope})
			if err != nil {
				return nil, err
			}
			var permissions []string
			for _, assignment := range assignments {
				definition, err := reg.GetRole(c, assignment.RoleID, types.ScopeFilter{})
				if err != nil {
					return nil, err
				}
				permissions = append(permissions, definition.Permissions...)
			}
			return permissions, nil
		}},
	})
	require.NoError(t, err)
	policy, err := auth.NewFreshnessPolicy(auth.FreshnessPolicyConfig{Owner: "fixture-owner", ApprovedAt: now, PropagationTarget: time.Minute, Operations: []auth.FreshnessOperationPolicy{{
		Operation: "resource.read", Risk: auth.OperationRiskNormalRead, RequiredPermission: "resource.read", RequiredAssurance: auth.AssuranceAAL1,
		MaxAuthenticationAge: time.Hour, MaxAccountStateAge: time.Minute, RefreshOnPermissionMismatch: true,
	}}})
	require.NoError(t, err)
	states, err := auth.NewCompositeAccountStateResolver(auth.CompositeAccountStateResolverConfig{Sources: []auth.NamedAccountStateSource{{Name: "sql", Source: auth.AccountStateSourceFunc(func(c context.Context, p auth.AuthenticatedPrincipal) (auth.AccountStateObservation, error) {
		current, err := users.GetByID(c, p.ApplicationSubject())
		if err != nil {
			return auth.AccountStateObservation{}, err
		}
		return auth.AccountStateObservation{State: auth.AccountState(current.Status), ObservedAt: time.Now().UTC()}, nil
	})}}})
	require.NoError(t, err)
	guard, err := auth.NewAuthorizationFreshnessGuard(auth.AuthorizationFreshnessGuardConfig{Policy: policy, AccountStates: states,
		PermissionVersions: auth.PermissionVersionResolverFunc(func(c context.Context, p auth.AuthenticatedPrincipal) (auth.PermissionVersionResult, error) {
			var version int
			var role string
			err := db.QueryRowContext(c, `SELECT v.version,u.user_role FROM host_authorization_versions v JOIN users u ON u.id=v.user_id WHERE u.id=?`, p.ApplicationSubject()).Scan(&version, &role)
			return auth.PermissionVersionResult{Role: role, Version: strconv.Itoa(version), ObservedAt: time.Now().UTC()}, err
		}), Permissions: scoped.ResolverFunc(),
	})
	require.NoError(t, err)
	principal, err := auth.NewAuthenticatedPrincipal(auth.AuthenticatedPrincipalInput{ApplicationSubject: user.ID.String(), Provider: "local", ProviderSubject: user.ID.String(), AssuranceLevel: "aal1", AuthenticationAt: now, ExpiresAt: now.Add(time.Hour), PermissionVersion: "1"})
	require.NoError(t, err)
	authorize := func(scope types.ScopeFilter) (auth.AuthorizationFreshnessResult, error) {
		return guard.Authorize(context.WithValue(ctx, selectedScopeKey{}, scope), auth.AuthorizationFreshnessRequest{Operation: "resource.read", Principal: principal})
	}
	result, err := authorize(a)
	require.NoError(t, err)
	require.Equal(t, auth.FreshnessAllowed, result.Decision)
	result, err = authorize(b)
	require.Error(t, err)
	require.Equal(t, auth.FreshnessReasonPermissionDenied, result.Reason)
	// Native assignment removal and the host-owned version change share a tx.
	// Reliable post-commit invalidation delivery remains a host integration gate.
	err = db.RunInTx(ctx, nil, func(c context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().Model((*registry.RoleAssignment)(nil)).Where("user_id = ? AND role_id = ?", user.ID, role.ID).Exec(c); err != nil {
			return err
		}
		_, err := tx.ExecContext(c, `UPDATE host_authorization_versions SET version = version + 1 WHERE user_id = ?`, user.ID)
		return err
	})
	require.NoError(t, err)
	result, err = authorize(a)
	require.Error(t, err)
	require.True(t, result.PermissionsRefreshed)
	require.Equal(t, "2", result.CurrentVersion)
	require.Equal(t, auth.FreshnessReasonPermissionDenied, result.Reason)
	revoked := auth.WithProviderSessionContext(context.WithValue(ctx, selectedScopeKey{}, a), auth.ProviderSession{ID: "session-a", Status: auth.ProviderSessionRevoked}, principal)
	result, err = guard.Authorize(revoked, auth.AuthorizationFreshnessRequest{Operation: "resource.read"})
	require.Error(t, err)
	require.Equal(t, auth.FreshnessReasonSessionInvalid, result.Reason)
	_, err = users.UpdateStatus(ctx, user.ID, auth.UserStatusDisabled)
	require.NoError(t, err)
	result, err = authorize(a)
	require.Error(t, err)
	require.Equal(t, auth.FreshnessReasonAccountState, result.Reason)
}
