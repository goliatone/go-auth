package csrf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSRFTemplateHelpersPerRendererFactory(t *testing.T) {
	original := getTemplateHelperFactory()
	t.Cleanup(func() { SetTemplateHelperFactory(original) })
	calls := 0
	SetTemplateHelperFactory(func(name, fallback string) any {
		calls++
		return "legacy:" + name + ":" + fallback
	})
	modern := CSRFTemplateHelpersWithFactory(func(name, fallback string) any {
		return "modern:" + name + ":" + fallback
	})
	plain := CSRFTemplateHelpersWithFactory(nil)
	require.Zero(t, calls, "scoped selection must not invoke the default factory")
	legacy := CSRFTemplateHelpers()
	require.Len(t, plain, 4)
	require.Equal(t, 4, calls)
	for name, value := range plain {
		require.Equal(t, "modern:"+name+":"+value.(string), modern[name])
		require.Equal(t, "legacy:"+name+":"+value.(string), legacy[name])
	}
}
