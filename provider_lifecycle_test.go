package auth

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func validAuthorizedOperation(action ProviderOperationAction) AuthorizedOperationContext {
	return AuthorizedOperationContext{
		OperationID:  "op-1",
		Action:       action,
		Permission:   "identity.manage",
		Actor:        ActorRef{ID: "admin-1", Type: "user"},
		Target:       ProviderOperationTarget{Provider: "supabase", Subject: "user-1"},
		Reason:       "support request",
		Environment:  "test",
		RequestID:    "request-1",
		AuthorizedAt: time.Now().UTC(),
	}
}

func TestAuthorizedOperationContextFailsClosed(t *testing.T) {
	valid := validAuthorizedOperation(ProviderActionSuspend)
	require.NoError(t, valid.Validate(ProviderActionSuspend, "test", "supabase"))

	tests := map[string]func(*AuthorizedOperationContext){
		"action":      func(v *AuthorizedOperationContext) { v.Action = ProviderActionActivate },
		"permission":  func(v *AuthorizedOperationContext) { v.Permission = "" },
		"actor":       func(v *AuthorizedOperationContext) { v.Actor.ID = "" },
		"target":      func(v *AuthorizedOperationContext) { v.Target.Subject = "" },
		"provider":    func(v *AuthorizedOperationContext) { v.Target.Provider = "" },
		"reason":      func(v *AuthorizedOperationContext) { v.Reason = "" },
		"environment": func(v *AuthorizedOperationContext) { v.Environment = "production" },
		"provider mismatch": func(v *AuthorizedOperationContext) {
			v.Target.Provider = "other"
		},
		"request": func(v *AuthorizedOperationContext) { v.RequestID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			require.ErrorIs(t, input.Validate(ProviderActionSuspend, "test", "supabase"), ErrProviderOperationUnauthorized)
		})
	}
}

func TestProviderOperationOutcomeRejectsUnknownStatus(t *testing.T) {
	require.NoError(t, (ProviderOperationOutcome{Status: ProviderOperationPending}).Validate())
	err := (ProviderOperationOutcome{Status: "invented"}).Validate()
	require.True(t, errors.Is(err, ErrProviderOperationInvalid))
}

func TestAuthorizationContinuationIsBoundedAndExpires(t *testing.T) {
	now := time.Now().UTC()
	require.NoError(t, (AuthorizationContinuation{
		AuthorizationID: "authorization-1",
		Environment:     "test",
		ExpiresAt:       now.Add(time.Minute),
	}).Validate(now))
	require.ErrorIs(t, (AuthorizationContinuation{
		AuthorizationID: "authorization-1",
		Environment:     "test",
		ExpiresAt:       now,
	}).Validate(now), ErrProviderOperationInvalid)
}

func TestAuthorizationDecisionRejectsUnsafeRedirect(t *testing.T) {
	result := AuthorizationDecisionResult{RedirectURL: "https://client.example/callback"}
	require.NoError(t, result.ValidateRedirect(func(u *url.URL) bool {
		return u.Host == "client.example" && u.Path == "/callback"
	}))
	result.RedirectURL = "https://attacker.example/callback"
	require.ErrorIs(t, result.ValidateRedirect(func(*url.URL) bool { return false }), ErrProviderOperationInvalid)
}

func TestAuthorizationRequestValidationRejectsBeforeTransport(t *testing.T) {
	now := time.Now().UTC()
	capability, err := NewTokenTargetCapability()
	require.NoError(t, err)
	principal, err := NewAuthenticatedPrincipal(AuthenticatedPrincipalInput{
		ApplicationSubject: "app-user-1",
		Provider:           "supabase",
		ProviderSubject:    "provider-user-1",
		ProviderSessionID:  "provider-session-1",
		ExpiresAt:          now.Add(time.Minute),
	})
	require.NoError(t, err)
	session := ProviderUserSession{
		SessionHandle: NewSecret("opaque-session-handle"),
		Binding: ProviderSessionBinding{
			Host:          "backoffice.example",
			ApplicationID: "backoffice",
			Environment:   "test",
			Provider:      "supabase",
			Issuer:        "https://project.supabase.co/auth/v1",
			ClientID:      "client-1",
		},
		Principal:   principal,
		TokenTarget: "supabase-authorization",
		Capability:  capability,
	}
	operation := validAuthorizedOperation(ProviderActionAuthorizationDetails)
	operation.Target.ObjectID = "authorization-1"
	operation.Target.Subject = "provider-user-1"
	operation.ProviderSessionID = "provider-session-1"
	request := AuthorizationDetailsRequest{
		Operation: operation,
		Continuation: AuthorizationContinuation{
			AuthorizationID: "authorization-1",
			Environment:     "test",
			ExpiresAt:       now.Add(time.Minute),
		},
		Session: session,
	}
	require.NoError(t, request.Validate("supabase", "test", now))

	request.Session.Binding.Environment = "production"
	require.ErrorIs(t, request.Validate("supabase", "test", now), ErrProviderOperationUnauthorized)

	request.Session = ProviderUserSession{}
	require.ErrorIs(t, request.Validate("supabase", "test", now), ErrProviderOperationUnauthorized)
}

func TestAuthorizationDecisionValidationBindsActionSessionAndCSRF(t *testing.T) {
	now := time.Now().UTC()
	request := AuthorizationDecisionRequest{
		Operation:       validAuthorizedOperation(ProviderActionAuthorizationApprove),
		AuthorizationID: "authorization-1",
		CSRFBinding:     "csrf-binding",
	}
	request.Operation.Target.ObjectID = request.AuthorizationID
	err := request.Validate(ProviderActionAuthorizationDeny, "supabase", "test", now)
	require.ErrorIs(t, err, ErrProviderOperationUnauthorized)
}
