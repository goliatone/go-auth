package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"
)

var (
	ErrProviderOperationInvalid      = errors.New("auth: invalid provider operation")
	ErrProviderOperationUnauthorized = errors.New("auth: provider operation is not authorized")
	ErrProviderOperationUnsupported  = errors.New("auth: provider operation is unsupported")
	ErrProviderOperationConflict     = errors.New("auth: provider operation conflicts with current state")
	ErrProviderOperationPending      = errors.New("auth: provider operation outcome is pending")
)

// ProviderOperationAction names a narrow provider-neutral operation. Hosts
// authorize these actions before invoking a provider implementation.
type ProviderOperationAction string

const (
	ProviderActionInvite               ProviderOperationAction = "identity.invite"
	ProviderActionStartRecovery        ProviderOperationAction = "identity.recovery.start"
	ProviderActionSuspend              ProviderOperationAction = "account.suspend"
	ProviderActionActivate             ProviderOperationAction = "account.activate"
	ProviderActionGetAccountState      ProviderOperationAction = "account.state.get"
	ProviderActionListFactors          ProviderOperationAction = "factor.list"
	ProviderActionRemoveFactor         ProviderOperationAction = "factor.remove"
	ProviderActionAuthorizationDetails ProviderOperationAction = "authorization.details"
	ProviderActionAuthorizationApprove ProviderOperationAction = "authorization.approve"
	ProviderActionAuthorizationDeny    ProviderOperationAction = "authorization.deny"
)

func (a ProviderOperationAction) valid() bool {
	switch a {
	case ProviderActionInvite,
		ProviderActionStartRecovery,
		ProviderActionSuspend,
		ProviderActionActivate,
		ProviderActionGetAccountState,
		ProviderActionListFactors,
		ProviderActionRemoveFactor,
		ProviderActionAuthorizationDetails,
		ProviderActionAuthorizationApprove,
		ProviderActionAuthorizationDeny:
		return true
	default:
		return false
	}
}

// ProviderOperationTarget identifies the provider-side object selected by an
// already-authorized host operation.
type ProviderOperationTarget struct {
	Provider           string
	ApplicationSubject string
	Subject            string
	ObjectID           string
}

type ProviderOperationAuthorizationRequest struct {
	Action      ProviderOperationAction
	Permission  string
	Actor       ActorRef
	Target      ProviderOperationTarget
	Reason      string
	Environment string
	RequestID   string
}

// ProviderOperationAuthorizer is host-owned. Provider adapters consume the
// resulting proof but never decide business permissions themselves.
type ProviderOperationAuthorizer interface {
	AuthorizeProviderOperation(context.Context, ProviderOperationAuthorizationRequest) (AuthorizedOperationContext, error)
}

// AuthorizedOperationContext is a typed proof that the host authorized one
// exact provider operation. It deliberately contains no credential or token.
type AuthorizedOperationContext struct {
	OperationID       string
	Action            ProviderOperationAction
	Permission        string
	Actor             ActorRef
	Target            ProviderOperationTarget
	Reason            string
	Environment       string
	RequestID         string
	ProviderSessionID string
	AuthorizedAt      time.Time
}

// Validate verifies that the proof is complete and bound to the expected
// action, environment, and target provider before any transport work occurs.
//
//nolint:gocyclo // Authorized-operation bindings are exhaustively checked at the provider boundary.
func (c AuthorizedOperationContext) Validate(expected ProviderOperationAction, environment, provider string) error {
	if !expected.valid() || c.Action != expected {
		return fmt.Errorf("%w: action mismatch", ErrProviderOperationUnauthorized)
	}
	if strings.TrimSpace(c.OperationID) == "" ||
		strings.TrimSpace(c.Permission) == "" ||
		strings.TrimSpace(c.Actor.ID) == "" ||
		strings.TrimSpace(c.Actor.Type) == "" ||
		strings.TrimSpace(c.Target.Provider) == "" ||
		strings.TrimSpace(c.Target.Subject) == "" ||
		strings.TrimSpace(c.Reason) == "" ||
		strings.TrimSpace(c.Environment) == "" ||
		strings.TrimSpace(c.RequestID) == "" ||
		c.AuthorizedAt.IsZero() {
		return fmt.Errorf("%w: incomplete authorization context", ErrProviderOperationUnauthorized)
	}
	if !strings.EqualFold(strings.TrimSpace(c.Environment), strings.TrimSpace(environment)) {
		return fmt.Errorf("%w: environment mismatch", ErrProviderOperationUnauthorized)
	}
	if provider = strings.TrimSpace(provider); provider != "" &&
		!strings.EqualFold(strings.TrimSpace(c.Target.Provider), provider) {
		return fmt.Errorf("%w: provider mismatch", ErrProviderOperationUnauthorized)
	}
	for field, value := range map[string]string{
		"operation_id":        c.OperationID,
		"permission":          c.Permission,
		"actor_id":            c.Actor.ID,
		"actor_type":          c.Actor.Type,
		"target_provider":     c.Target.Provider,
		"application_subject": c.Target.ApplicationSubject,
		"target_subject":      c.Target.Subject,
		"target_object":       c.Target.ObjectID,
		"reason":              c.Reason,
		"environment":         c.Environment,
		"request_id":          c.RequestID,
		"provider_session_id": c.ProviderSessionID,
	} {
		if len(value) > 1024 {
			return fmt.Errorf("%w: %s exceeds limit", ErrProviderOperationInvalid, field)
		}
	}
	return nil
}

type ProviderOperationStatus string

const (
	ProviderOperationSucceeded       ProviderOperationStatus = "succeeded"
	ProviderOperationAlreadyComplete ProviderOperationStatus = "already_complete"
	ProviderOperationPending         ProviderOperationStatus = "pending"
	ProviderOperationUnsupported     ProviderOperationStatus = "unsupported"
	ProviderOperationConflict        ProviderOperationStatus = "conflict"
	ProviderOperationFailed          ProviderOperationStatus = "failed"
)

type ProviderOperationOutcome struct {
	Status                ProviderOperationStatus
	Retryable             bool
	ProviderRequestID     string
	ProviderSessionEffect ProviderSessionEffect
	ResidualAccessExpires time.Time
}

func (o ProviderOperationOutcome) Validate() error {
	switch o.Status {
	case ProviderOperationSucceeded,
		ProviderOperationAlreadyComplete,
		ProviderOperationPending,
		ProviderOperationUnsupported,
		ProviderOperationConflict,
		ProviderOperationFailed:
		return nil
	default:
		return fmt.Errorf("%w: invalid outcome status", ErrProviderOperationInvalid)
	}
}

type ProviderSessionEffect string

const (
	ProviderSessionEffectNone       ProviderSessionEffect = "none"
	ProviderSessionEffectCurrent    ProviderSessionEffect = "current"
	ProviderSessionEffectNamed      ProviderSessionEffect = "named"
	ProviderSessionEffectAllForUser ProviderSessionEffect = "all_for_user"
)

type ProviderDeliveryStatus string

const (
	ProviderDeliverySent      ProviderDeliveryStatus = "sent"
	ProviderDeliveryDuplicate ProviderDeliveryStatus = "duplicate"
	ProviderDeliveryPending   ProviderDeliveryStatus = "pending"
	ProviderDeliveryFailed    ProviderDeliveryStatus = "failed"
)

type ProviderDeliveryOutcome struct {
	ProviderOperationOutcome
	Delivery ProviderDeliveryStatus
}

type ProviderAccountState string

const (
	ProviderAccountStateActive    ProviderAccountState = "active"
	ProviderAccountStateSuspended ProviderAccountState = "suspended"
	ProviderAccountStateDisabled  ProviderAccountState = "disabled"
	ProviderAccountStateUnknown   ProviderAccountState = "unknown"
)

type AccountStateResult struct {
	ProviderOperationOutcome
	State     ProviderAccountState
	UpdatedAt time.Time
}

type ProviderFactorType string

const (
	ProviderFactorTOTP     ProviderFactorType = "totp"
	ProviderFactorPhone    ProviderFactorType = "phone"
	ProviderFactorWebAuthn ProviderFactorType = "webauthn"
	ProviderFactorUnknown  ProviderFactorType = "unknown"
)

type ProviderFactorState string

const (
	ProviderFactorVerified   ProviderFactorState = "verified"
	ProviderFactorUnverified ProviderFactorState = "unverified"
)

type ProviderFactor struct {
	ID           string
	Type         ProviderFactorType
	State        ProviderFactorState
	FriendlyName string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ProviderFactorsResult struct {
	ProviderOperationOutcome
	Factors []ProviderFactor
}

type InviteRequest struct {
	Operation AuthorizedOperationContext
	Email     string
	ReturnURL string
}

type RecoveryRequest struct {
	Operation AuthorizedOperationContext
	Email     string
	ReturnURL string
}

type AccountLifecycleRequest struct {
	Operation AuthorizedOperationContext
}

type FactorListRequest struct {
	Operation AuthorizedOperationContext
}

type FactorRemoveRequest struct {
	Operation AuthorizedOperationContext
	FactorID  string
	// KnownState is an optional optimistic-concurrency expectation. Provider
	// implementations must derive security behavior from authoritative state.
	KnownState ProviderFactorState
	// RemainingVerifiedFactors is an optional expectation for the authoritative
	// verified-factor count. A zero value means no caller expectation.
	RemainingVerifiedFactors int
	AllowLastVerified        bool
}

type IdentityLifecycle interface {
	Invite(context.Context, InviteRequest) (ProviderDeliveryOutcome, error)
	StartRecovery(context.Context, RecoveryRequest) (ProviderDeliveryOutcome, error)
}

type AccountLifecycle interface {
	Suspend(context.Context, AccountLifecycleRequest) (AccountStateResult, error)
	Activate(context.Context, AccountLifecycleRequest) (AccountStateResult, error)
	GetAccountState(context.Context, AccountLifecycleRequest) (AccountStateResult, error)
}

type FactorLifecycle interface {
	ListFactors(context.Context, FactorListRequest) (ProviderFactorsResult, error)
	RemoveFactor(context.Context, FactorRemoveRequest) (ProviderOperationOutcome, error)
}

// ProviderUserSession identifies the validated central provider session whose
// user token may be resolved internally. It cannot carry a raw token.
type ProviderUserSession struct {
	SessionHandle Secret
	Binding       ProviderSessionBinding
	Principal     AuthenticatedPrincipal
	TokenTarget   string
	Capability    TokenTargetCapability
}

func (s ProviderUserSession) Validate(provider, environment string, now time.Time) error {
	if s.SessionHandle.IsZero() || strings.TrimSpace(s.TokenTarget) == "" || !s.Capability.valid() {
		return fmt.Errorf("%w: central provider session is incomplete", ErrProviderOperationUnauthorized)
	}
	if strings.TrimSpace(s.Principal.ProviderSessionID()) == "" ||
		!strings.EqualFold(strings.TrimSpace(s.Principal.Provider()), strings.TrimSpace(provider)) {
		return fmt.Errorf("%w: central provider session mismatch", ErrProviderOperationUnauthorized)
	}
	if !s.Principal.ExpiresAt().IsZero() && !now.Before(s.Principal.ExpiresAt()) {
		return fmt.Errorf("%w: central provider session expired", ErrProviderOperationUnauthorized)
	}
	if err := s.Binding.Validate(); err != nil {
		return fmt.Errorf("%w: invalid provider session binding", ErrProviderOperationUnauthorized)
	}
	if !strings.EqualFold(strings.TrimSpace(s.Binding.Provider), strings.TrimSpace(provider)) ||
		!strings.EqualFold(strings.TrimSpace(s.Binding.Environment), strings.TrimSpace(environment)) ||
		(strings.TrimSpace(s.Principal.ClientID()) != "" &&
			strings.TrimSpace(s.Binding.ClientID) != strings.TrimSpace(s.Principal.ClientID())) {
		return fmt.Errorf("%w: provider session binding mismatch", ErrProviderOperationUnauthorized)
	}
	return nil
}

type AuthorizationContinuation struct {
	AuthorizationID string
	Environment     string
	ExpiresAt       time.Time
}

func (c AuthorizationContinuation) Validate(now time.Time) error {
	id := strings.TrimSpace(c.AuthorizationID)
	if id == "" || len(id) > 1024 || strings.TrimSpace(c.Environment) == "" ||
		c.ExpiresAt.IsZero() || !now.Before(c.ExpiresAt) {
		return fmt.Errorf("%w: invalid authorization continuation", ErrProviderOperationInvalid)
	}
	return nil
}

type AuthorizationDetails struct {
	AuthorizationID string
	ClientID        string
	ClientName      string
	Scopes          []string
	RedirectURL     string
	ExpiresAt       time.Time
	// DecisionProof is server-held, tamper-evident continuity state. It is
	// intentionally omitted from JSON and default formatting.
	DecisionProof Secret
}

func (d AuthorizationDetails) Clone() AuthorizationDetails {
	d.Scopes = slices.Clone(d.Scopes)
	return d
}

func (d AuthorizationDetails) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AuthorizationID string    `json:"authorization_id"`
		ClientID        string    `json:"client_id"`
		ClientName      string    `json:"client_name"`
		Scopes          []string  `json:"scopes"`
		RedirectURL     string    `json:"redirect_url"`
		ExpiresAt       time.Time `json:"expires_at"`
	}{
		AuthorizationID: d.AuthorizationID,
		ClientID:        d.ClientID,
		ClientName:      d.ClientName,
		Scopes:          slices.Clone(d.Scopes),
		RedirectURL:     d.RedirectURL,
		ExpiresAt:       d.ExpiresAt,
	})
}

type AuthorizationDetailsRequest struct {
	Operation    AuthorizedOperationContext
	Continuation AuthorizationContinuation
	Session      ProviderUserSession
}

func (r AuthorizationDetailsRequest) Validate(provider, environment string, now time.Time) error {
	if err := r.Operation.Validate(ProviderActionAuthorizationDetails, environment, provider); err != nil {
		return err
	}
	if err := r.Continuation.Validate(now); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(r.Continuation.Environment), strings.TrimSpace(environment)) ||
		strings.TrimSpace(r.Operation.Target.ObjectID) != strings.TrimSpace(r.Continuation.AuthorizationID) {
		return fmt.Errorf("%w: authorization continuation mismatch", ErrProviderOperationUnauthorized)
	}
	if err := r.Session.Validate(provider, environment, now); err != nil {
		return err
	}
	if strings.TrimSpace(r.Operation.Target.Subject) != r.Session.Principal.ProviderSubject() {
		return fmt.Errorf("%w: authorization user mismatch", ErrProviderOperationUnauthorized)
	}
	if strings.TrimSpace(r.Operation.ProviderSessionID) == "" ||
		strings.TrimSpace(r.Operation.ProviderSessionID) != r.Session.Principal.ProviderSessionID() {
		return fmt.Errorf("%w: authorization provider session mismatch", ErrProviderOperationUnauthorized)
	}
	return nil
}

type AuthorizationDecisionRequest struct {
	Operation       AuthorizedOperationContext
	AuthorizationID string
	ClientID        string
	Session         ProviderUserSession
	Scopes          []string
	CSRFBinding     string
	// DecisionProof must be the server-held proof returned by details retrieval.
	DecisionProof Secret
}

//nolint:gocyclo // Decision request proof and session bindings remain explicit and fail closed.
func (r AuthorizationDecisionRequest) Validate(action ProviderOperationAction, provider, environment string, now time.Time) error {
	if action != ProviderActionAuthorizationApprove && action != ProviderActionAuthorizationDeny {
		return fmt.Errorf("%w: invalid authorization decision", ErrProviderOperationUnauthorized)
	}
	if err := r.Operation.Validate(action, environment, provider); err != nil {
		return err
	}
	authorizationID := strings.TrimSpace(r.AuthorizationID)
	if authorizationID == "" || len(authorizationID) > 1024 ||
		authorizationID != strings.TrimSpace(r.Operation.Target.ObjectID) ||
		strings.TrimSpace(r.ClientID) == "" || len(r.ClientID) > 1024 ||
		strings.TrimSpace(r.CSRFBinding) == "" || len(r.CSRFBinding) > 1024 ||
		r.DecisionProof.IsZero() {
		return fmt.Errorf("%w: authorization decision mismatch", ErrProviderOperationUnauthorized)
	}
	if len(compactStrings(r.Scopes)) != len(r.Scopes) {
		return fmt.Errorf("%w: invalid requested scopes", ErrProviderOperationInvalid)
	}
	if err := r.Session.Validate(provider, environment, now); err != nil {
		return err
	}
	if strings.TrimSpace(r.Operation.Target.Subject) != r.Session.Principal.ProviderSubject() {
		return fmt.Errorf("%w: authorization user mismatch", ErrProviderOperationUnauthorized)
	}
	if strings.TrimSpace(r.Operation.ProviderSessionID) == "" ||
		strings.TrimSpace(r.Operation.ProviderSessionID) != r.Session.Principal.ProviderSessionID() {
		return fmt.Errorf("%w: authorization provider session mismatch", ErrProviderOperationUnauthorized)
	}
	return nil
}

type AuthorizationDecisionResult struct {
	ProviderOperationOutcome
	RedirectURL string
}

func (r AuthorizationDecisionResult) HTTPRedirectURL() string { return r.RedirectURL }
func (r AuthorizationDecisionResult) String() string {
	return fmt.Sprintf("auth.AuthorizationDecisionResult{Status:%q ProviderRequestID:%q RedirectURL:%s}",
		r.Status, r.ProviderRequestID, redactedSecret)
}
func (r AuthorizationDecisionResult) GoString() string { return r.String() }
func (r AuthorizationDecisionResult) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(r.String()))
}
func (r AuthorizationDecisionResult) LogValue() slog.Value { return slog.StringValue(r.String()) }
func (r AuthorizationDecisionResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Status            ProviderOperationStatus `json:"status"`
		ProviderRequestID string                  `json:"provider_request_id,omitempty"`
	}{r.Status, r.ProviderRequestID})
}

func (r AuthorizationDecisionResult) ValidateRedirect(allow func(*url.URL) bool) error {
	parsed, err := url.Parse(strings.TrimSpace(r.RedirectURL))
	if err != nil || !parsed.IsAbs() || parsed.User != nil || allow == nil || !allow(parsed) {
		return fmt.Errorf("%w: invalid provider redirect", ErrProviderOperationInvalid)
	}
	return nil
}

type AuthorizationDecisionService interface {
	GetAuthorizationDetails(context.Context, AuthorizationDetailsRequest) (AuthorizationDetails, error)
	ApproveAuthorization(context.Context, AuthorizationDecisionRequest) (AuthorizationDecisionResult, error)
	DenyAuthorization(context.Context, AuthorizationDecisionRequest) (AuthorizationDecisionResult, error)
}
