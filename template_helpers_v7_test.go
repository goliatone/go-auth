package auth

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	p6 "github.com/flosch/pongo2/v6"
	p7 "github.com/flosch/pongo2/v7"
	"github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/require"
)

func TestTemplateHelpersForPongo2V7Fallbacks(t *testing.T) {
	helpers := TemplateHelpersForPongo2V7()
	for name, fallback := range csrf.CSRFTemplateHelpersWithFactory(nil) {
		fn, ok := helpers[name].(func(*p7.ExecutionContext) string)
		require.True(t, ok, "%s must use the v7 execution context", name)
		require.Equal(t, fallback, fn(nil))
		require.Equal(t, fallback, fn(&p7.ExecutionContext{Public: p7.Context{}}))
		require.Equal(t, fallback, fn(&p7.ExecutionContext{Public: p7.Context{csrf.DefaultTemplateHelpersKey: "invalid"}}))
		require.Equal(t, "request-value", fn(&p7.ExecutionContext{Public: p7.Context{
			csrf.DefaultTemplateHelpersKey: map[string]any{name: "request-value"},
		}}))
		_, legacy := TemplateHelpers()[name].(func(*p6.ExecutionContext) string)
		require.True(t, legacy, "v7 setup changed the legacy %s helper", name)
	}
}

func TestTemplateHelpersDualRuntimeRequests(t *testing.T) {
	const source = `{{ csrf_token }}|{{ csrf_header_name }}|{{ csrf_field|safe }}|{{ csrf_meta|safe }}|{{ roles.member }}`
	for _, reload := range []bool{false, true} {
		for _, modernFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("reload=%t/modern-first=%t", reload, modernFirst), func(t *testing.T) {
				cfg := csrfViewConfig(t, source).WithReload(reload).
					WithFunctions(TemplateHelpers()).WithFiberV3Functions(TemplateHelpersForPongo2V7())
				factories := []func() (router.Views, error){
					func() (router.Views, error) { return router.InitializeViewEngine(cfg) },
					func() (router.Views, error) { return router.InitializeFiberV3ViewEngine(cfg) },
				}
				if modernFirst {
					factories[0], factories[1] = factories[1], factories[0]
				}
				var views []router.Views
				for _, factory := range factories {
					view, err := factory()
					require.NoError(t, err)
					views = append(views, view)
				}
				var workers sync.WaitGroup
				for i := range 12 {
					workers.Go(func() {
						token := fmt.Sprintf("request-%d", i)
						ctx := router.NewMockContext()
						ctx.LocalsMock["custom-token"] = token
						ctx.LocalsMock["custom-token_field"] = "custom-field"
						ctx.LocalsMock["custom-token_header"] = "X-Custom-CSRF"
						data := map[string]any{csrf.DefaultTemplateHelpersKey: csrf.CSRFTemplateHelpersWithRouter(ctx, "custom-token")}
						want := token + `|X-Custom-CSRF|<input type="hidden" name="custom-field" value="` + token + `">|<meta name="csrf-token" content="` + token + `">|member`
						for _, view := range views {
							var out bytes.Buffer
							if err := view.Render(&out, "page", data); err != nil || out.String() != want {
								t.Errorf("request values: got %q want %q err=%v", out.String(), want, err)
							}
						}
					})
				}
				workers.Wait()
			})
		}
	}
}

func TestTemplateHelpersForPongo2V7Safety(t *testing.T) {
	views, err := router.InitializeFiberV3ViewEngine(csrfViewConfig(t, `{{ csrf_token }}`).WithFunctions(TemplateHelpersForPongo2V7()))
	require.NoError(t, err)
	for _, value := range []any{"<script>bad</script>", p7.AsSafeValue("<script>bad</script>")} {
		var out bytes.Buffer
		err = views.Render(&out, "page", map[string]any{csrf.DefaultTemplateHelpersKey: map[string]any{"csrf_token": value}})
		require.NoError(t, err)
		require.Equal(t, "&lt;script&gt;bad&lt;/script&gt;", out.String(), "helper results must remain plain strings")
	}
	for _, value := range []any{p6.AsValue(false), p6.AsSafeValue("<script>bad</script>"), p7.AsValue(p6.AsValue(false))} {
		var out bytes.Buffer
		err = views.Render(&out, "page", map[string]any{csrf.DefaultTemplateHelpersKey: map[string]any{"csrf_token": value}})
		require.ErrorContains(t, err, "pongo2/v6.Value")
		require.Empty(t, out.String())
	}
}

func csrfViewConfig(t *testing.T, source string) *router.SimpleViewConfig {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "page.html"), []byte(source), 0600))
	return router.NewSimpleViewConfig(dir).WithDebug(false)
}
