package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	p6 "github.com/flosch/pongo2/v6"
	p7 "github.com/flosch/pongo2/v7"
	fiber2 "github.com/gofiber/fiber/v2"
	fiber3 "github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/require"
)

type viewPolicyClaims struct{ *JWTClaims }

func (c *viewPolicyClaims) CanEdit(resource string) bool {
	return resource == "custom-policy" || resource == "*"
}

type recordingAuthViews struct {
	data    any
	name    string
	layouts []string
	err     error
}

func (v *recordingAuthViews) Load() error { return v.err }
func (v *recordingAuthViews) Render(w io.Writer, name string, bind any, layouts ...string) error {
	v.data, v.name, v.layouts = bind, name, layouts
	if v.err != nil {
		return v.err
	}
	_, err := io.WriteString(w, "rendered")
	return err
}

func viewTestClaims() *JWTClaims {
	return &JWTClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "subject", ExpiresAt: jwt.NewNumericDate(time.Unix(2000000000, 0)), IssuedAt: jwt.NewNumericDate(time.Unix(1700000000, 0))},
		UID: "<user>", UserRole: "guest", Resources: map[string]string{"posts": "admin"}, Metadata: map[string]any{"tenant": "tenant-one", "secret": "private"}}
}

func TestTemplateViewsProjectionAndPolicy(t *testing.T) {
	claims := &viewPolicyClaims{viewTestClaims()}
	var nilClaims *JWTClaims
	nested := router.ViewContext{"user": claims}
	input := map[string]any{"custom_jwt": claims, "template_helpers": nested, "users": []any{claims, nilClaims}}
	target := &recordingAuthViews{}
	views := NewTemplateViews(target)
	require.NoError(t, views.Load())
	var out bytes.Buffer
	require.NoError(t, views.Render(&out, "page", input, "layout"))
	require.Equal(t, "rendered", out.String())
	require.Equal(t, "page", target.name)
	require.Equal(t, []string{"layout"}, target.layouts)
	projected := target.data.(map[string]any)
	for _, value := range []any{projected["custom_jwt"], projected["template_helpers"].(map[string]any)["user"], projected["users"].([]any)[0]} {
		v := value.(templateClaimsView)
		require.Equal(t, claims.UserID(), v.UserID())
		require.Equal(t, claims.Subject(), v.Subject())
		require.Equal(t, claims.Role(), v.Role())
		require.Equal(t, claims.Expires(), v.Expires())
		require.Equal(t, claims.IssuedAt(), v.IssuedAt())
		require.True(t, hasRole(v, "admin")) // resource role, not the global guest role
		require.True(t, v.CanEdit("custom-policy"))
		require.True(t, canEdit(v), "helper must preserve custom wildcard policy")
		require.False(t, v.CanEdit("posts")) // custom override must survive
		for _, resource := range []string{"posts", "other"} {
			require.Equal(t, claims.CanRead(resource), v.CanRead(resource))
			require.Equal(t, claims.CanCreate(resource), v.CanCreate(resource))
			require.Equal(t, claims.CanDelete(resource), v.CanDelete(resource))
		}
		require.Equal(t, claims.IsAtLeast("member"), v.IsAtLeast("member"))
		roles := v.ResourceRoles()
		roles["posts"] = "guest"
		require.Equal(t, "admin", v.Resources["posts"])
		v.Resources["posts"] = "member"
		require.Equal(t, "admin", claims.Resources["posts"])
	}
	require.Nil(t, projected["users"].([]any)[1])
	projected["template_helpers"].(map[string]any)["user"] = nil
	projected["users"].([]any)[0] = nil
	require.Same(t, claims, input["custom_jwt"])
	require.Same(t, claims, nested["user"])
	require.Same(t, claims, input["users"].([]any)[0])
	require.Equal(t, "private", claims.Metadata["secret"])
	require.Nil(t, NewTemplateViews(nil))
	sentinel := errors.New("engine error")
	target.err = sentinel
	require.ErrorIs(t, views.Load(), sentinel)
	require.ErrorIs(t, views.Render(&out, "page", nil), sentinel)
}

type unsafeAuthViewModel struct{}

func (unsafeAuthViewModel) Dynamic() any { return p6.AsSafeValue("unsafe") }

func TestTemplateViewsRendererSafety(t *testing.T) {
	cfg := csrfViewConfig(t, `{{ user.UID }}|{{ user.Metadata }}|{{ user.ClaimsMetadata }}|{{ user.claims.Metadata.secret }}`)
	engine, err := router.InitializeFiberV3ViewEngine(cfg)
	require.NoError(t, err)
	views := NewTemplateViews(engine)
	var out bytes.Buffer
	require.NoError(t, views.Render(&out, "page", map[string]any{"user": viewTestClaims()}))
	require.Equal(t, "&lt;user&gt;|||", out.String())
	for _, value := range []any{p6.AsValue(false), p7.AsValue(p6.AsValue(false)), unsafeAuthViewModel{}} {
		out.Reset()
		err := views.Render(&out, "page", map[string]any{"user": viewTestClaims(), "unsafe": value})
		require.Error(t, err, "unsafe value %T", value)
		require.Empty(t, out.String())
	}

	// Dynamic helpers are supported, but their returned values are still checked.
	helperEngine, err := router.InitializeFiberV3ViewEngine(csrfViewConfig(t, `{{ unsafe() }}`))
	require.NoError(t, err)
	out.Reset()
	require.ErrorContains(t, NewTemplateViews(helperEngine).Render(&out, "page", map[string]any{
		"unsafe": func() any { return p6.AsSafeValue("unsafe") },
	}), "pongo2/v6.Value")
	require.Empty(t, out.String())
	cycle := map[string]any{}
	cycle["self"] = cycle
	out.Reset()
	require.ErrorContains(t, views.Render(&out, "page", cycle), "cyclic or excessively deep")
	require.Empty(t, out.String())
}

type viewTokenValidator struct{ claims *JWTClaims }

func (v viewTokenValidator) Validate(token string) (jwtware.AuthClaims, error) {
	if token != "valid" {
		return nil, errors.New("invalid token")
	}
	return v.claims, nil
}

func TestTemplateViewsPreserveRequestAuthentication(t *testing.T) {
	const source = `{{ account.UID }}|{{ has_role(account, "admin") }}|{{ account.CanEdit("posts") }}|{{ can_edit(account) }}|{{ template_helpers.current_user.UserID }}|{{ custom_jwt.Subject }}`
	for _, mode := range []string{"v2-default", "v2-wrapped", "v3-wrapped"} {
		t.Run(mode, func(t *testing.T) {
			cfg := csrfViewConfig(t, source).WithFunctions(TemplateHelpers()).WithFiberV3Functions(TemplateHelpersForPongo2V7())
			var views router.Views
			var err error
			if mode == "v3-wrapped" {
				views, err = router.InitializeFiberV3ViewEngine(cfg)
			} else {
				views, err = router.InitializeViewEngine(cfg)
			}
			require.NoError(t, err)
			if mode != "v2-default" {
				views = NewTemplateViews(views)
			}
			claims := viewTestClaims()
			middleware := jwtware.New(jwtware.Config{SigningKey: jwtware.SigningKey{Key: []byte("test-key")}, TokenValidator: viewTokenValidator{claims}, ContextKey: "custom_jwt", TemplateUserKey: "account", ContextEnricher: ContextEnricherAdapter, RequiredRole: "admin",
				ErrorHandler: func(c router.Context, err error) error {
					return c.Status(http.StatusUnauthorized).SendString(err.Error())
				}})
			handler := middleware(func(c router.Context) error {
				nested := map[string]any{"current_user": claims}
				c.Locals("template_helpers", nested)
				originalContext := c.Context()
				actor, ok := ActorFromRouterContext(c)
				if !ok || actor.ActorID != claims.UserID() || actor.TenantID != "tenant-one" {
					return errors.New("actor state missing")
				}
				renderer, ok := router.AsTemplateRenderer(c)
				if !ok {
					return errors.New("render capability missing")
				}
				b, err := renderer.RenderToBytes("page", nil)
				if err != nil {
					return err
				}
				var out bytes.Buffer
				if err := renderer.RenderToWriter(&out, "page", nil); err != nil {
					return err
				}
				if string(b) != out.String() {
					return errors.New("render paths differ")
				}
				if err := c.Render("page", nil); err != nil {
					return err
				}
				stored, ok := GetClaims(c.Context())
				afterActor, actorOK := ActorFromRouterContext(c)
				if !ok || stored != claims || !actorOK || afterActor != actor || c.Context() != originalContext || c.Locals("custom_jwt") != claims || c.Locals("account") != claims || nested["current_user"] != claims || claims.Metadata["secret"] != "private" {
					return errors.New("render changed authentication state")
				}
				return nil
			})
			var request func(*http.Request) (*http.Response, error)
			if mode == "v3-wrapped" {
				server := router.NewFiberV3Adapter(func(*fiber3.App) *fiber3.App { return fiber3.New(fiber3.Config{Views: views, PassLocalsToViews: true}) })
				server.Router().Get("/page", handler)
				request = func(req *http.Request) (*http.Response, error) { return server.WrappedRouter().Test(req) }
			} else {
				server := router.NewFiberAdapter(func(*fiber2.App) *fiber2.App { return fiber2.New(fiber2.Config{Views: views, PassLocalsToViews: true}) })
				server.Router().Get("/page", handler)
				request = func(req *http.Request) (*http.Response, error) { return server.WrappedRouter().Test(req) }
			}
			for _, token := range []string{"", "invalid", "valid"} {
				req := httptest.NewRequestWithContext(context.Background(), "GET", "/page", nil)
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				resp, err := request(req)
				require.NoError(t, err)
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.NoError(t, resp.Body.Close())
				if token != "valid" {
					require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
					continue
				}
				require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
				require.Equal(t, "&lt;user&gt;|True|True|False|&lt;user&gt;|subject", string(body))
			}
		})
	}
}
