package goadmin

import auth "github.com/goliatone/go-auth"

// ProviderServices is an optional provider-neutral service bundle exposed to
// host-owned go-admin route and panel composition. The adapter stores these
// boundaries but does not authorize operations, render provider UI, or invoke
// them during SSO setup.
type ProviderServices struct {
	IdentityLifecycle auth.IdentityLifecycle
	AccountLifecycle  auth.AccountLifecycle
	FactorLifecycle   auth.FactorLifecycle
	Authorization     auth.AuthorizationDecisionService
	Coordinator       *auth.LifecycleCoordinator
}

func (s ProviderServices) Enabled() bool {
	return s.IdentityLifecycle != nil ||
		s.AccountLifecycle != nil ||
		s.FactorLifecycle != nil ||
		s.Authorization != nil ||
		s.Coordinator != nil
}
