package auth

import (
	"github.com/flosch/pongo2/v7"

	"github.com/goliatone/go-auth/middleware/csrf"
)

// TemplateHelpersForPongo2V7 returns auth helpers for a pongo2/v7 renderer, such as
// go-router's explicit Fiber v3 view engine. CSRF values are resolved from each
// execution context and returned as plain strings; the renderer owns escaping.
// This does not change TemplateHelpers or the default CSRF helper factory.
func TemplateHelpersForPongo2V7() map[string]any {
	return templateHelpers(csrf.CSRFTemplateHelpersWithFactory(csrfTemplateHelperFactoryV7))
}

func csrfTemplateHelperFactoryV7(name, fallback string) any {
	return func(execCtx *pongo2.ExecutionContext) string {
		if execCtx == nil {
			return fallback
		}
		return resolveTemplateHelperData(execCtx.Public, name, fallback)
	}
}
