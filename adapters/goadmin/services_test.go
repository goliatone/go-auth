package goadmin

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/goliatone/go-admin/admin"
	auth "github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth/provider/oidc"
)

type authorizationServiceStub struct {
	calls atomic.Int32
	err   error
}

func (s *authorizationServiceStub) GetAuthorizationDetails(context.Context, auth.AuthorizationDetailsRequest) (auth.AuthorizationDetails, error) {
	s.calls.Add(1)
	return auth.AuthorizationDetails{}, s.err
}
func (s *authorizationServiceStub) ApproveAuthorization(context.Context, auth.AuthorizationDecisionRequest) (auth.AuthorizationDecisionResult, error) {
	s.calls.Add(1)
	return auth.AuthorizationDecisionResult{}, s.err
}
func (s *authorizationServiceStub) DenyAuthorization(context.Context, auth.AuthorizationDecisionRequest) (auth.AuthorizationDecisionResult, error) {
	s.calls.Add(1)
	return auth.AuthorizationDecisionResult{}, s.err
}

func TestProviderServicesAreOptionalAndDoNotChangeRouteContract(t *testing.T) {
	without := NewModule()
	if without.ProviderServices().Enabled() {
		t.Fatal("provider services should be disabled by default")
	}
	before := without.RouteContract()
	service := &authorizationServiceStub{}
	with := NewModule(WithProviderServices(ProviderServices{Authorization: service}))
	if !with.ProviderServices().Enabled() || with.ProviderServices().Authorization != service {
		t.Fatal("expected opt-in authorization service")
	}
	after := with.RouteContract()
	if before.Slug != after.Slug || len(before.UIRoutes) != len(after.UIRoutes) {
		t.Fatalf("service injection must not add presentation routes: before=%#v after=%#v", before, after)
	}
	if service.calls.Load() != 0 {
		t.Fatal("module construction must not invoke provider services")
	}
}

func TestSetupSSOExposesProviderServicesForHostRouteComposition(t *testing.T) {
	adm, err := admin.New(admin.Config{}, admin.Dependencies{})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	service := &authorizationServiceStub{}
	bundle := ProviderServices{Authorization: service}
	cfg := testAuthConfig{}
	result, err := SetupSSO(QuickstartConfig{
		Admin:      adm,
		AuthConfig: cfg,
		Auther:     auth.NewAuthenticator(fakeIdentityProvider{}, cfg),
		Browser:    stubBrowserFlow{},
		ProviderEntries: []oidc.ProviderInfo{
			{Key: "oidc", Label: "OIDC", LoginURL: "/sso/login/oidc"},
		},
		ProviderServices: bundle,
	})
	if err != nil {
		t.Fatalf("SetupSSO: %v", err)
	}
	if result.ProviderServices.Authorization != service ||
		result.Module.ProviderServices().Authorization != service {
		t.Fatal("expected the host-owned service boundary in result and module")
	}
	if service.calls.Load() != 0 {
		t.Fatal("SSO setup must not authorize or invoke provider operations")
	}
}

func TestProviderServicesPreserveHostAuthorizationFailure(t *testing.T) {
	service := &authorizationServiceStub{err: auth.ErrProviderOperationUnauthorized}
	module := NewModule(WithProviderServices(ProviderServices{Authorization: service}))

	_, err := module.ProviderServices().Authorization.ApproveAuthorization(
		context.Background(),
		auth.AuthorizationDecisionRequest{},
	)
	if !errors.Is(err, auth.ErrProviderOperationUnauthorized) {
		t.Fatalf("expected host-composed route to preserve authorization failure, got %v", err)
	}
	if service.calls.Load() != 1 {
		t.Fatalf("expected exactly one host invocation, got %d", service.calls.Load())
	}
}
