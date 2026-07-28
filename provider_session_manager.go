package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"
)

type ProviderSessionManagerConfig struct {
	Repository     ProviderSessionRepository
	Cipher         TokenCipher
	Binding        ProviderSessionBinding
	IdleLifetime   time.Duration
	MaxLifetime    time.Duration
	TouchInterval  time.Duration
	RefreshLease   time.Duration
	Refresher      ProviderTokenRefresher
	Reconciler     ProviderTokenReconciler
	RevocationHook ProviderRevocationHook
	TargetRegistry *TokenTargetRegistry
	AccessPolicy   TokenAccessPolicy
	ActivitySink   ActivitySink
	Deployment     ProviderSessionDeployment
	Operations     *ProviderSessionOperationsConfig
}

type ProviderSessionManager struct {
	repository     ProviderSessionRepository
	cipher         TokenCipher
	binding        ProviderSessionBinding
	idleLifetime   time.Duration
	maxLifetime    time.Duration
	touchInterval  time.Duration
	refreshLease   time.Duration
	refresher      ProviderTokenRefresher
	reconciler     ProviderTokenReconciler
	revocationHook ProviderRevocationHook
	targetRegistry *TokenTargetRegistry
	accessPolicy   TokenAccessPolicy
	activitySink   ActivitySink
	refreshGroup   singleflight.Group
}

//nolint:gocyclo // Construction validates each deployment and operations invariant explicitly.
func NewProviderSessionManager(cfg ProviderSessionManagerConfig) (*ProviderSessionManager, error) {
	if cfg.Repository == nil || cfg.Cipher == nil {
		return nil, fmt.Errorf("%w: repository and cipher are required", ErrProviderSessionInvalid)
	}
	if err := cfg.Binding.Validate(); err != nil {
		return nil, err
	}
	if cfg.IdleLifetime <= 0 || cfg.MaxLifetime <= 0 || cfg.IdleLifetime > cfg.MaxLifetime {
		return nil, fmt.Errorf("%w: valid idle and maximum lifetimes are required", ErrProviderSessionInvalid)
	}
	if cfg.TouchInterval <= 0 {
		cfg.TouchInterval = DefaultProviderSessionTouch
	}
	if cfg.RefreshLease == 0 {
		cfg.RefreshLease = DefaultProviderRefreshLease
	}
	if cfg.RefreshLease < 5*time.Second || cfg.RefreshLease > 2*time.Minute {
		return nil, fmt.Errorf("%w: refresh lease must be between 5 seconds and 2 minutes", ErrProviderSessionInvalid)
	}
	if err := cfg.Deployment.Validate(); err != nil {
		return nil, err
	}
	environment := strings.ToLower(strings.TrimSpace(cfg.Binding.Environment))
	legacyProductionName := environment == "prod" || environment == "production"
	if cfg.Deployment.RequiresOperations() || legacyProductionName {
		if cfg.Operations == nil {
			return nil, fmt.Errorf("%w: production operations configuration is required", ErrProviderSessionInvalid)
		}
		if err := cfg.Operations.Validate(cfg.Binding, cfg.IdleLifetime, cfg.MaxLifetime); err != nil {
			return nil, err
		}
	} else if cfg.Operations != nil {
		if err := cfg.Operations.Validate(cfg.Binding, cfg.IdleLifetime, cfg.MaxLifetime); err != nil {
			return nil, err
		}
	}
	return &ProviderSessionManager{
		repository:     cfg.Repository,
		cipher:         cfg.Cipher,
		binding:        cfg.Binding.normalized(),
		idleLifetime:   cfg.IdleLifetime,
		maxLifetime:    cfg.MaxLifetime,
		touchInterval:  cfg.TouchInterval,
		refreshLease:   cfg.RefreshLease,
		refresher:      cfg.Refresher,
		reconciler:     cfg.Reconciler,
		revocationHook: cfg.RevocationHook,
		targetRegistry: cfg.TargetRegistry,
		accessPolicy:   cfg.AccessPolicy,
		activitySink:   normalizeActivitySink(cfg.ActivitySink),
	}, nil
}

//nolint:gocyclo // Session and token bindings are checked explicitly before persistence.
func (m *ProviderSessionManager) CreateProviderSession(ctx context.Context, principal AuthenticatedPrincipal, tokens ProviderTokenSet) (ProviderSessionCreation, error) {
	if m == nil || m.repository == nil || m.cipher == nil {
		return ProviderSessionCreation{}, ErrProviderSessionUnavailable
	}
	if principal.ApplicationSubject() == "" || principal.ProviderSubject() == "" ||
		principal.Provider() != m.binding.Provider || principal.ClientID() != m.binding.ClientID {
		return ProviderSessionCreation{}, ErrProviderSessionBinding
	}
	if tokens.AccessToken().IsZero() && tokens.RefreshToken().IsZero() && tokens.IDToken().IsZero() {
		return ProviderSessionCreation{}, ErrInvalidTokenSet
	}
	rawHandle, err := randomProviderSessionValue(32)
	if err != nil {
		return ProviderSessionCreation{}, err
	}
	internalID := uuid.NewString()
	localSessionID := uuid.NewString()
	principal, err = principal.BindLocalSessionID(localSessionID)
	if err != nil {
		return ProviderSessionCreation{}, err
	}
	now := time.Now().UTC()
	session := ProviderSession{
		ID:             internalID,
		LocalSessionID: localSessionID,
		Principal:      NewPrincipalSnapshot(principal),
		Binding:        m.binding,
		Status:         ProviderSessionAvailable,
		TokenRevision:  1,
		CreatedAt:      now,
		LastSeenAt:     now,
		IdleExpiresAt:  now.Add(m.idleLifetime),
		MaxExpiresAt:   now.Add(m.maxLifetime),
	}
	payload, err := marshalProviderTokenSet(tokens)
	if err != nil {
		return ProviderSessionCreation{}, fmt.Errorf("%w: encode token set", ErrProviderTokenCipher)
	}
	envelope, err := m.cipher.Seal(ctx, payload, providerSessionAssociatedData(session, session.TokenRevision))
	if err != nil {
		return ProviderSessionCreation{}, fmt.Errorf("%w: seal token set", ErrProviderTokenCipher)
	}
	lookup := sha256.Sum256([]byte(rawHandle))
	stored, err := m.repository.Create(ctx, ProviderSessionCreate{
		Session: session, LookupHash: lookup[:], Tokens: envelope,
	})
	if err != nil {
		return ProviderSessionCreation{}, err
	}
	storedPrincipal, err := stored.Principal.Principal()
	if err != nil {
		return ProviderSessionCreation{}, ErrProviderSessionInvalid
	}
	m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionCreated, stored, ProviderSessionActivityMetadata{
		Result: "succeeded",
	})
	return ProviderSessionCreation{
		Handle: NewSecret(rawHandle), Session: stored, Principal: storedPrincipal,
	}, nil
}

func (m *ProviderSessionManager) ResolveProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSession, AuthenticatedPrincipal, error) {
	if m == nil || handle.IsZero() {
		return ProviderSession{}, AuthenticatedPrincipal{}, ErrProviderSessionNotFound
	}
	if !m.binding.Equal(binding) {
		return ProviderSession{}, AuthenticatedPrincipal{}, ErrProviderSessionBinding
	}
	lookup := sha256.Sum256([]byte(handle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, lookup[:], binding, m.touchInterval)
	if err != nil {
		return ProviderSession{}, AuthenticatedPrincipal{}, err
	}
	principal, err := resolved.Session.Principal.Principal()
	if err != nil {
		return ProviderSession{}, AuthenticatedPrincipal{}, ErrProviderSessionInvalid
	}
	return resolved.Session, principal, nil
}

func (m *ProviderSessionManager) ReencryptProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSession, error) {
	if m == nil || handle.IsZero() || !m.binding.Equal(binding) {
		return ProviderSession{}, ErrProviderSessionBinding
	}
	lookup := sha256.Sum256([]byte(handle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, lookup[:], binding, m.touchInterval)
	if err != nil {
		return ProviderSession{}, err
	}
	plaintext, err := m.cipher.Open(ctx, resolved.Tokens, providerSessionAssociatedData(resolved.Session, resolved.Session.TokenRevision))
	if err != nil {
		return ProviderSession{}, fmt.Errorf("%w: open current token set", ErrProviderTokenCipher)
	}
	nextRevision := resolved.Session.TokenRevision + 1
	nextEnvelope, err := m.cipher.Seal(ctx, plaintext, providerSessionAssociatedData(resolved.Session, nextRevision))
	if err != nil {
		return ProviderSession{}, fmt.Errorf("%w: reseal token set", ErrProviderTokenCipher)
	}
	return m.repository.ReplaceCiphertext(ctx, resolved.Session.ID, resolved.Session.TokenRevision, nextEnvelope)
}

func (m *ProviderSessionManager) RotateProviderSessionHandle(ctx context.Context, handle Secret, binding ProviderSessionBinding) (Secret, ProviderSession, error) {
	if m == nil || handle.IsZero() || !m.binding.Equal(binding) {
		return Secret{}, ProviderSession{}, ErrProviderSessionBinding
	}
	oldLookup := sha256.Sum256([]byte(handle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, oldLookup[:], binding, m.touchInterval)
	if err != nil {
		return Secret{}, ProviderSession{}, err
	}
	rawHandle, err := randomProviderSessionValue(32)
	if err != nil {
		return Secret{}, ProviderSession{}, err
	}
	newLookup := sha256.Sum256([]byte(rawHandle))
	updated, err := m.repository.RotateHandle(ctx, resolved.Session.ID, resolved.Session.TokenRevision, oldLookup[:], newLookup[:])
	if err != nil {
		return Secret{}, ProviderSession{}, err
	}
	return NewSecret(rawHandle), updated, nil
}

//nolint:gocyclo // Refresh ownership, ambiguity, and reconciliation branches remain explicit.
func (m *ProviderSessionManager) RefreshProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSession, error) {
	if m == nil || m.refresher == nil || handle.IsZero() || !m.binding.Equal(binding) {
		return ProviderSession{}, ErrProviderSessionUnavailable
	}
	resolved, waited, err := m.resolveForRefresh(ctx, handle, binding)
	if err != nil {
		return ProviderSession{}, err
	}
	if waited {
		return resolved.Session, nil
	}
	value, err, _ := m.refreshGroup.Do(resolved.Session.ID, func() (any, error) {
		current, waitedForPeer, resolveErr := m.resolveForRefresh(ctx, handle, binding)
		if resolveErr != nil {
			return ProviderSession{}, resolveErr
		}
		if waitedForPeer {
			return current.Session, nil
		}
		attemptID, randomErr := randomProviderSessionValue(24)
		if randomErr != nil {
			return ProviderSession{}, randomErr
		}
		claim, claimErr := m.repository.ClaimRefresh(
			ctx,
			current.Session.ID,
			current.Session.TokenRevision,
			attemptID,
			m.refreshLease,
		)
		if claimErr != nil {
			if errors.Is(claimErr, ErrProviderRefreshInProgress) {
				return m.waitForRefresh(ctx, handle, binding)
			}
			return ProviderSession{}, claimErr
		}
		if !claim.Acquired {
			return m.waitForRefresh(ctx, handle, binding)
		}
		tokens, openErr := m.openProviderTokenSet(ctx, claim.Session, claim.Tokens)
		if openErr != nil {
			_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, attemptID, claim.Session.TokenRevision, "token envelope unavailable")
			return ProviderSession{}, openErr
		}
		if tokens.RefreshToken().IsZero() ||
			(!tokens.RefreshExpiresAt().IsZero() && !time.Now().UTC().Before(tokens.RefreshExpiresAt())) {
			_, _, _ = m.repository.Revoke(ctx, claim.Session.ID, "refresh token unavailable")
			return ProviderSession{}, ErrProviderRefreshRejected
		}
		result, refreshErr := m.refresher.RefreshProviderTokens(ctx, ProviderRefreshRequest{
			Session: claim.Session, AttemptID: attemptID,
			RefreshToken: tokens.RefreshToken(), CurrentTokens: tokens,
		})
		if refreshErr != nil {
			if errors.Is(refreshErr, ErrProviderRefreshRejected) {
				_, _, _ = m.repository.Revoke(ctx, claim.Session.ID, "provider rejected refresh")
				return ProviderSession{}, ErrProviderRefreshRejected
			}
			return m.reconcileAmbiguousRefresh(ctx, claim, tokens, refreshErr)
		}
		refreshed, mergeErr := mergeRefreshedTokenSet(tokens, result.Tokens)
		if mergeErr != nil {
			_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, attemptID, claim.Session.TokenRevision, "invalid refresh result")
			return ProviderSession{}, mergeErr
		}
		return m.commitRefreshedTokens(ctx, claim, refreshed)
	})
	if err != nil {
		return ProviderSession{}, err
	}
	session, ok := value.(ProviderSession)
	if !ok {
		return ProviderSession{}, ErrProviderSessionUnavailable
	}
	return session, nil
}

func (m *ProviderSessionManager) resolveForRefresh(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSessionResolution, bool, error) {
	lookup := sha256.Sum256([]byte(handle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, lookup[:], binding, m.touchInterval)
	if errors.Is(err, ErrProviderRefreshInProgress) {
		session, waitErr := m.waitForRefresh(ctx, handle, binding)
		if waitErr != nil {
			return ProviderSessionResolution{}, false, waitErr
		}
		return ProviderSessionResolution{Session: session}, true, nil
	}
	return resolved, false, err
}

func (m *ProviderSessionManager) waitForRefresh(ctx context.Context, handle Secret, binding ProviderSessionBinding) (ProviderSession, error) {
	waitCtx := ctx
	cancel := func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		waitCtx, cancel = context.WithTimeout(ctx, m.refreshLease+time.Second)
	}
	defer cancel()
	lookup := sha256.Sum256([]byte(handle.Reveal()))
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		resolved, err := m.repository.Resolve(waitCtx, lookup[:], binding, m.touchInterval)
		switch {
		case err == nil:
			return resolved.Session, nil
		case errors.Is(err, ErrProviderRefreshInProgress):
		case errors.Is(err, ErrProviderSessionConflict):
		default:
			return ProviderSession{}, err
		}
		select {
		case <-waitCtx.Done():
			return ProviderSession{}, ErrProviderSessionUnavailable
		case <-ticker.C:
		}
	}
}

func (m *ProviderSessionManager) openProviderTokenSet(ctx context.Context, session ProviderSession, envelope TokenEnvelope) (ProviderTokenSet, error) {
	plaintext, err := m.cipher.Open(ctx, envelope, providerSessionAssociatedData(session, session.TokenRevision))
	if err != nil {
		return ProviderTokenSet{}, fmt.Errorf("%w: open token set", ErrProviderTokenCipher)
	}
	return unmarshalProviderTokenSet(plaintext)
}

func (m *ProviderSessionManager) commitRefreshedTokens(ctx context.Context, claim ProviderRefreshClaim, tokens ProviderTokenSet) (ProviderSession, error) {
	nextRevision := claim.Session.TokenRevision + 1
	payload, err := marshalProviderTokenSet(tokens)
	if err != nil {
		_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "encode refresh result failed")
		return ProviderSession{}, ErrProviderTokenCipher
	}
	envelope, err := m.cipher.Seal(ctx, payload, providerSessionAssociatedData(claim.Session, nextRevision))
	if err != nil {
		_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "seal refresh result failed")
		return ProviderSession{}, ErrProviderTokenCipher
	}
	session, err := m.repository.CommitRefresh(ctx, ProviderRefreshCommit{
		SessionID: claim.Session.ID, AttemptID: claim.AttemptID, BaseRevision: claim.Session.TokenRevision,
		Tokens: envelope, AccessExpiresAt: tokens.AccessExpiresAt(), RefreshExpiresAt: tokens.RefreshExpiresAt(),
	})
	if err == nil {
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRefreshed, session, ProviderSessionActivityMetadata{
			Result: "succeeded",
		})
	}
	return session, err
}

func (m *ProviderSessionManager) reconcileAmbiguousRefresh(ctx context.Context, claim ProviderRefreshClaim, _ ProviderTokenSet, _ error) (ProviderSession, error) {
	if m.reconciler == nil {
		_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "ambiguous provider refresh")
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionUncertain, claim.Session, ProviderSessionActivityMetadata{
			Result: "reauthentication_required",
			Reason: ProviderSessionReasonFromLegacy("ambiguous provider refresh"),
		})
		return ProviderSession{}, ErrProviderRefreshAmbiguous
	}
	result, err := m.reconciler.ReconcileProviderRefresh(ctx, ProviderRefreshReconcileRequest{
		Session: claim.Session, AttemptID: claim.AttemptID, BaseRevision: claim.Session.TokenRevision,
	})
	if err != nil || result.Status == ProviderRefreshReconcileUnknown {
		_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "refresh reconciliation unavailable")
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionUncertain, claim.Session, ProviderSessionActivityMetadata{
			Result: "reauthentication_required",
			Reason: ProviderSessionReasonFromLegacy("refresh reconciliation unavailable"),
		})
		return ProviderSession{}, ErrProviderRefreshAmbiguous
	}
	switch result.Status {
	case ProviderRefreshReconciledTokens:
		if result.Tokens.AccessToken().IsZero() && result.Tokens.RefreshToken().IsZero() {
			_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "empty reconciled token set")
			return ProviderSession{}, ErrProviderRefreshAmbiguous
		}
		return m.commitRefreshedTokens(ctx, claim, result.Tokens)
	case ProviderRefreshReconciledRevoked:
		_, _, _ = m.repository.Revoke(ctx, claim.Session.ID, "provider reconciliation reported revoked")
		return ProviderSession{}, ErrProviderRefreshRejected
	default:
		_ = m.repository.MarkRefreshUncertain(ctx, claim.Session.ID, claim.AttemptID, claim.Session.TokenRevision, "unknown reconciliation result")
		return ProviderSession{}, ErrProviderRefreshAmbiguous
	}
}

func (m *ProviderSessionManager) RevokeCurrentProviderSession(ctx context.Context, handle Secret, binding ProviderSessionBinding, reason string) error {
	if m == nil || handle.IsZero() || !m.binding.Equal(binding) {
		return ErrProviderSessionBinding
	}
	lookup := sha256.Sum256([]byte(handle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, lookup[:], binding, m.touchInterval)
	if err != nil {
		if errors.Is(err, ErrProviderSessionRevoked) {
			return nil
		}
		return err
	}
	return m.revokeLoadedProviderSession(ctx, resolved, reason)
}

func (m *ProviderSessionManager) RevokeProviderSession(ctx context.Context, sessionID, reason string) error {
	if m == nil || strings.TrimSpace(sessionID) == "" {
		return ErrProviderSessionInvalid
	}
	resolved, err := m.repository.Load(ctx, sessionID)
	if err != nil {
		return err
	}
	if resolved.Session.Status == ProviderSessionRevoked {
		return nil
	}
	return m.revokeLoadedProviderSession(ctx, resolved, reason)
}

func (m *ProviderSessionManager) RevokeUserProviderSessions(ctx context.Context, applicationSubject, reason string) error {
	if m == nil || strings.TrimSpace(applicationSubject) == "" {
		return ErrProviderSessionInvalid
	}
	sessions, err := m.repository.RevokeUser(ctx, applicationSubject, boundedProviderSessionReason(reason))
	if err != nil {
		return err
	}
	var firstErr error
	for _, session := range sessions {
		resolved, loadErr := m.repository.Load(ctx, session.ID)
		if loadErr != nil {
			if firstErr == nil {
				firstErr = loadErr
			}
			m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
				Reason:       ProviderSessionReasonFromLegacy(reason),
				RemoteStatus: ProviderRemoteRevocationFailed,
			})
			continue
		}
		outcome, remoteErr := m.invokeProviderRevocation(ctx, resolved, reason)
		if updateErr := m.repository.UpdateRemoteRevocation(ctx, session.ID, outcome); updateErr != nil && firstErr == nil {
			firstErr = updateErr
		}
		if remoteErr != nil && firstErr == nil {
			firstErr = remoteErr
		}
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
			Reason:          ProviderSessionReasonFromLegacy(reason),
			RemoteStatus:    outcome.Status,
			RemoteRetryable: outcome.Retryable,
		})
	}
	return firstErr
}

func (m *ProviderSessionManager) InvalidateProviderSession(ctx context.Context, sessionID, reason string) error {
	if m == nil || strings.TrimSpace(sessionID) == "" {
		return ErrProviderSessionInvalid
	}
	session, changed, err := m.repository.Revoke(ctx, sessionID, boundedProviderSessionReason(reason))
	if err != nil || !changed {
		return err
	}
	m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
		Reason:       ProviderSessionReasonFromLegacy(reason),
		RemoteStatus: ProviderRemoteRevocationPending,
		LocalOnly:    true,
	})
	return nil
}

func (m *ProviderSessionManager) InvalidateUserProviderSessions(ctx context.Context, applicationSubject, reason string) error {
	if m == nil || strings.TrimSpace(applicationSubject) == "" {
		return ErrProviderSessionInvalid
	}
	sessions, err := m.repository.RevokeUser(ctx, applicationSubject, boundedProviderSessionReason(reason))
	if err != nil {
		return err
	}
	for _, session := range sessions {
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
			Reason:       ProviderSessionReasonFromLegacy(reason),
			RemoteStatus: ProviderRemoteRevocationPending,
			LocalOnly:    true,
		})
	}
	return nil
}

func (m *ProviderSessionManager) InvalidateProviderSessions(
	ctx context.Context,
	scope ProviderSessionInvalidationScope,
	limit int,
	reason string,
) (int, bool, error) {
	if m == nil || m.repository == nil || limit <= 0 || limit > 10_000 {
		return 0, false, ErrProviderSessionInvalid
	}
	scoped, ok := m.repository.(ProviderSessionScopeRepository)
	if !ok {
		return 0, false, ErrProviderSessionUnavailable
	}
	sessions, more, err := scoped.RevokeScope(ctx, scope, limit, boundedProviderSessionReason(reason))
	if err != nil {
		return 0, false, err
	}
	for _, session := range sessions {
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
			Reason:       ProviderSessionReasonFromLegacy(reason),
			RemoteStatus: ProviderRemoteRevocationPending,
			LocalOnly:    true,
		})
	}
	return len(sessions), more, nil
}

func (m *ProviderSessionManager) ApplyProviderSessionLifecycle(
	ctx context.Context,
	transition ProviderSessionLifecycleTransition,
) (ProviderSessionLifecycleFence, []ProviderSession, error) {
	if m == nil || m.repository == nil {
		return ProviderSessionLifecycleFence{}, nil, ErrProviderSessionUnavailable
	}
	lifecycle, ok := m.repository.(ProviderSessionLifecycleRepository)
	if !ok {
		return ProviderSessionLifecycleFence{}, nil, ErrProviderSessionUnavailable
	}
	fence, sessions, err := lifecycle.AdvanceProviderSessionLifecycle(ctx, transition)
	if err != nil {
		return ProviderSessionLifecycleFence{}, nil, err
	}
	for _, session := range sessions {
		m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
			Reason:              ProviderSessionReasonFromLegacy(transition.Reason),
			RemoteStatus:        ProviderRemoteRevocationPending,
			LocalOnly:           true,
			LifecycleGeneration: fence.Generation,
		})
	}
	return fence, sessions, nil
}

var _ ProviderSessionScopeInvalidator = (*ProviderSessionManager)(nil)
var _ ProviderSessionLifecycleInvalidator = (*ProviderSessionManager)(nil)

//nolint:gocyclo // Token target, policy, refresh, and binding gates stay sequential and fail closed.
func (m *ProviderSessionManager) AccessToken(ctx context.Context, request UserTokenRequest) (Secret, error) {
	if m == nil || m.targetRegistry == nil || request.SessionHandle.IsZero() || !m.binding.Equal(request.Binding) {
		return Secret{}, ErrProviderTokenTarget
	}
	target, err := m.targetRegistry.Resolve(request.Target, request.Capability)
	if err != nil {
		return Secret{}, err
	}
	lookup := sha256.Sum256([]byte(request.SessionHandle.Reveal()))
	resolved, err := m.repository.Resolve(ctx, lookup[:], request.Binding, m.touchInterval)
	if err != nil {
		return Secret{}, err
	}
	current, ok := ProviderSessionFromContext(ctx)
	if !ok || current.Session.ID != resolved.Session.ID || current.Session.LocalSessionID != resolved.Session.LocalSessionID {
		return Secret{}, ErrProviderTokenPolicy
	}
	if bindingErr := validateTargetSessionBinding(target, resolved.Session); bindingErr != nil {
		return Secret{}, bindingErr
	}
	if target.RequirePolicy {
		if m.accessPolicy == nil {
			return Secret{}, ErrProviderTokenPolicyUnavailable
		}
		if policyErr := m.accessPolicy.AuthorizeProviderToken(ctx, TokenAccessPolicyRequest{
			Session: resolved.Session, Target: target,
		}); policyErr != nil {
			if errors.Is(policyErr, ErrProviderTokenPolicyUnavailable) {
				return Secret{}, ErrProviderTokenPolicyUnavailable
			}
			return Secret{}, ErrProviderTokenPolicy
		}
	}
	tokens, err := m.openProviderTokenSet(ctx, resolved.Session, resolved.Tokens)
	if err != nil {
		return Secret{}, err
	}
	if tokens.AccessToken().IsZero() {
		return Secret{}, ErrProviderTokenTarget
	}
	if !tokens.AccessExpiresAt().IsZero() && !time.Now().UTC().Add(30*time.Second).Before(tokens.AccessExpiresAt()) {
		if _, refreshErr := m.RefreshProviderSession(ctx, request.SessionHandle, request.Binding); refreshErr != nil {
			return Secret{}, refreshErr
		}
		resolved, err = m.repository.Resolve(ctx, lookup[:], request.Binding, m.touchInterval)
		if err != nil {
			return Secret{}, err
		}
		tokens, err = m.openProviderTokenSet(ctx, resolved.Session, resolved.Tokens)
		if err != nil {
			return Secret{}, err
		}
	}
	if err := validateTargetTokenBinding(target, resolved.Session, tokens); err != nil {
		return Secret{}, err
	}
	m.emitProviderSessionEvent(ctx, ActivityEventProviderTokenAccessed, resolved.Session, ProviderSessionActivityMetadata{
		Target: target.TelemetryName,
		Result: "succeeded",
	})
	return tokens.AccessToken(), nil
}

func validateTargetSessionBinding(target TokenTarget, session ProviderSession) error {
	if target.Provider != session.Binding.Provider ||
		strings.TrimRight(target.Issuer, "/") != strings.TrimRight(session.Binding.Issuer, "/") ||
		target.ClientID != session.Binding.ClientID {
		return ErrProviderTokenTarget
	}
	return nil
}

func validateTargetTokenBinding(target TokenTarget, session ProviderSession, tokens ProviderTokenSet) error {
	context, ok := tokens.AccessContext()
	if !ok {
		return ErrProviderTokenTarget
	}
	if strings.TrimRight(context.Issuer, "/") != strings.TrimRight(target.Issuer, "/") ||
		context.ClientID != target.ClientID ||
		context.Subject != session.Principal.ProviderSubject {
		return ErrProviderTokenTarget
	}
	if providerSessionID := strings.TrimSpace(session.Principal.ProviderSessionID); providerSessionID != "" &&
		context.SessionID != providerSessionID {
		return ErrProviderTokenTarget
	}
	for _, audience := range []string{target.Audience, target.Resource} {
		if strings.TrimSpace(audience) != "" && !containsProviderValue(context.Audiences, audience) {
			return ErrProviderTokenTarget
		}
	}
	scopes := tokens.Scopes()
	for _, required := range target.RequiredScopes {
		if !containsProviderValue(scopes, required) {
			return ErrProviderTokenTarget
		}
	}
	if !context.ExpiresAt.IsZero() && !time.Now().UTC().Before(context.ExpiresAt) {
		return ErrProviderTokenTarget
	}
	return nil
}

func containsProviderValue(values []string, expected string) bool {
	expected = strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

func (m *ProviderSessionManager) revokeLoadedProviderSession(ctx context.Context, resolved ProviderSessionResolution, reason string) error {
	session, changed, err := m.repository.Revoke(ctx, resolved.Session.ID, boundedProviderSessionReason(reason))
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	outcome, remoteErr := m.invokeProviderRevocation(ctx, resolved, reason)
	if updateErr := m.repository.UpdateRemoteRevocation(ctx, session.ID, outcome); updateErr != nil {
		return updateErr
	}
	m.emitProviderSessionEvent(ctx, ActivityEventProviderSessionRevoked, session, ProviderSessionActivityMetadata{
		Reason:          ProviderSessionReasonFromLegacy(reason),
		RemoteStatus:    outcome.Status,
		RemoteRetryable: outcome.Retryable,
	})
	return remoteErr
}

func (m *ProviderSessionManager) invokeProviderRevocation(ctx context.Context, resolved ProviderSessionResolution, reason string) (ProviderRemoteRevocationOutcome, error) {
	if m.revocationHook == nil {
		return ProviderRemoteRevocationOutcome{Status: ProviderRemoteRevocationUnsupported}, nil
	}
	tokens, err := m.openProviderTokenSet(ctx, resolved.Session, resolved.Tokens)
	if err != nil {
		return ProviderRemoteRevocationOutcome{Status: ProviderRemoteRevocationFailed, Retryable: false}, err
	}
	safeReason := ProviderSessionReasonFromLegacy(reason)
	outcome, err := m.revocationHook.RevokeProviderSession(ctx, ProviderRevocationRequest{
		Session:           resolved.Session,
		Reason:            string(safeReason.Code),
		ReasonCode:        safeReason.Code,
		ReasonFingerprint: safeReason.DetailFingerprint,
		Tokens:            tokens,
	})
	if validationErr := outcome.Validate(); validationErr != nil {
		return ProviderRemoteRevocationOutcome{
			Status: ProviderRemoteRevocationFailed,
		}, errors.Join(err, validationErr)
	}
	return outcome, err
}

// RetryRemoteRevocations executes already-locally-revoked remote work claimed
// through a bounded durable lease. It never changes local session usability.
//
//nolint:funlen,gocyclo // Retry processing keeps terminal, retained-work, and safe-error outcomes explicit.
func (m *ProviderSessionManager) RetryRemoteRevocations(
	ctx context.Context,
	policy ProviderRemoteRevocationClaimPolicy,
) (ProviderRemoteRevocationRetryResult, error) {
	if m == nil || m.repository == nil {
		return ProviderRemoteRevocationRetryResult{}, ErrProviderSessionUnavailable
	}
	remoteRepository, ok := m.repository.(ProviderRemoteRevocationRepository)
	if !ok {
		return ProviderRemoteRevocationRetryResult{}, ErrProviderSessionUnavailable
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = 10
	}
	claims, err := remoteRepository.ClaimRemoteRevocations(ctx, policy)
	if err != nil {
		return ProviderRemoteRevocationRetryResult{}, err
	}
	result := ProviderRemoteRevocationRetryResult{Claimed: len(claims)}
	var attemptErrors []error
	for _, claim := range claims {
		if claim.Session.Status != ProviderSessionRevoked ||
			strings.TrimSpace(claim.LeaseOwner) == "" ||
			claim.LeaseUntil.IsZero() ||
			claim.LeaseRemaining <= 0 {
			attemptErrors = append(attemptErrors, ErrProviderSessionConflict)
			continue
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, claim.LeaseRemaining)
		tokens, openErr := m.openProviderTokenSet(attemptCtx, claim.Session, claim.Tokens)
		outcome := ProviderRemoteRevocationOutcome{Status: ProviderRemoteRevocationFailed}
		var remoteErr error
		safeCode := ""
		if openErr != nil {
			remoteErr = openErr
			safeCode = "ciphertext_unavailable"
		} else if m.revocationHook == nil {
			outcome = ProviderRemoteRevocationOutcome{Status: ProviderRemoteRevocationUnsupported}
		} else {
			outcome, remoteErr = m.revocationHook.RevokeProviderSession(attemptCtx, ProviderRevocationRequest{
				Session:           claim.Session,
				Reason:            string(claim.Session.RevocationReasonCode),
				ReasonCode:        claim.Session.RevocationReasonCode,
				ReasonFingerprint: claim.Session.RevocationReasonFingerprint,
				Tokens:            tokens,
			})
			if validationErr := outcome.Validate(); validationErr != nil {
				remoteErr = errors.Join(remoteErr, validationErr)
				outcome = ProviderRemoteRevocationOutcome{Status: ProviderRemoteRevocationFailed}
				safeCode = "invalid_remote_outcome"
			}
		}
		cancelAttempt()
		terminal := !outcome.Retryable || claim.Attempt >= policy.MaxAttempts
		retryDelay := time.Duration(0)
		if !terminal {
			retryDelay = providerRemoteRetryDelay(claim.Attempt)
			if safeCode == "" {
				safeCode = "remote_retry_scheduled"
			}
		} else {
			if outcome.Status == ProviderRemoteRevocationSucceeded ||
				outcome.Status == ProviderRemoteRevocationUnsupported {
				safeCode = ""
			} else if safeCode == "" {
				safeCode = "remote_retry_terminal"
			}
		}
		completionErr := remoteRepository.CompleteRemoteRevocation(ctx, ProviderRemoteRevocationCompletion{
			SessionID:      claim.Session.ID,
			RemoteRevision: claim.RemoteRevision,
			LeaseOwner:     claim.LeaseOwner,
			LeaseUntil:     claim.LeaseUntil,
			Outcome:        outcome,
			RetryDelay:     retryDelay,
			SafeErrorCode:  safeCode,
			Terminal:       terminal,
		})
		if completionErr != nil {
			attemptErrors = append(attemptErrors, completionErr)
		} else if terminal {
			result.Terminal++
			if outcome.Status == ProviderRemoteRevocationSucceeded ||
				outcome.Status == ProviderRemoteRevocationUnsupported {
				result.Succeeded++
			}
		} else {
			result.Retried++
		}
		if remoteErr != nil {
			attemptErrors = append(attemptErrors, remoteErr)
		}
	}
	return result, errors.Join(attemptErrors...)
}

func providerRemoteRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 11 {
		attempt = 11
	}
	delay := time.Minute * time.Duration(1<<(attempt-1))
	if delay > 24*time.Hour {
		return 24 * time.Hour
	}
	return delay
}

func (m *ProviderSessionManager) emitProviderSessionEvent(
	ctx context.Context,
	eventType ActivityEventType,
	session ProviderSession,
	metadata ProviderSessionActivityMetadata,
) {
	if m == nil || m.activitySink == nil {
		return
	}
	event, err := NewProviderSessionActivityEvent(eventType, session, metadata, time.Now().UTC())
	if err != nil {
		return
	}
	_ = m.activitySink.Record(ctx, event)
}

func boundedProviderSessionReason(reason string) string {
	return EncodeProviderSessionReason(ProviderSessionReasonFromLegacy(reason))
}

func mergeRefreshedTokenSet(current, refreshed ProviderTokenSet) (ProviderTokenSet, error) {
	if refreshed.AccessToken().IsZero() {
		return ProviderTokenSet{}, ErrInvalidTokenSet
	}
	refreshToken := refreshed.RefreshToken()
	if refreshToken.IsZero() {
		refreshToken = current.RefreshToken()
	}
	idToken := refreshed.IDToken()
	if idToken.IsZero() {
		idToken = current.IDToken()
	}
	tokenType := refreshed.TokenType()
	if tokenType == "" {
		tokenType = current.TokenType()
	}
	scopes := refreshed.Scopes()
	if len(scopes) == 0 {
		scopes = current.Scopes()
	}
	acquiredAt := refreshed.AcquiredAt()
	if acquiredAt.IsZero() {
		acquiredAt = time.Now().UTC()
	}
	refreshExpiresAt := refreshed.RefreshExpiresAt()
	if refreshExpiresAt.IsZero() {
		refreshExpiresAt = current.RefreshExpiresAt()
	}
	idExpiresAt := refreshed.IDExpiresAt()
	if idExpiresAt.IsZero() {
		idExpiresAt = current.IDExpiresAt()
	}
	var idContext *ValidatedTokenContext
	if value, ok := refreshed.IDContext(); ok {
		idContext = &value
	} else if value, ok := current.IDContext(); ok {
		idContext = &value
	}
	var accessContext *ValidatedTokenContext
	if value, ok := refreshed.AccessContext(); ok {
		accessContext = &value
	}
	metadata := refreshed.Metadata()
	if len(metadata) == 0 {
		metadata = current.Metadata()
	}
	return NewProviderTokenSet(ProviderTokenSetInput{
		AccessToken: refreshed.AccessToken(), RefreshToken: refreshToken, IDToken: idToken,
		TokenType: tokenType, Scopes: scopes, AcquiredAt: acquiredAt,
		AccessExpiresAt: refreshed.AccessExpiresAt(), RefreshExpiresAt: refreshExpiresAt, IDExpiresAt: idExpiresAt,
		IDContext: idContext, AccessContext: accessContext, Metadata: metadata,
	})
}

func providerSessionAssociatedData(session ProviderSession, revision int64) []byte {
	b := session.Binding.normalized()
	return []byte(strings.Join([]string{
		"provider-session-v1",
		session.ID,
		session.LocalSessionID,
		b.Host,
		b.ApplicationID,
		b.Environment,
		b.TenantID,
		b.Provider,
		b.Issuer,
		b.ClientID,
		fmt.Sprintf("%d", revision),
	}, "\x00"))
}

type providerTokenPayload struct {
	AccessToken      string                 `json:"access_token,omitempty"`
	RefreshToken     string                 `json:"refresh_token,omitempty"`
	IDToken          string                 `json:"id_token,omitempty"`
	TokenType        string                 `json:"token_type,omitempty"`
	Scopes           []string               `json:"scopes,omitempty"`
	AcquiredAt       time.Time              `json:"acquired_at"`
	AccessExpiresAt  time.Time              `json:"access_expires_at"`
	RefreshExpiresAt time.Time              `json:"refresh_expires_at"`
	IDExpiresAt      time.Time              `json:"id_expires_at"`
	IDContext        *ValidatedTokenContext `json:"id_context,omitempty"`
	AccessContext    *ValidatedTokenContext `json:"access_context,omitempty"`
	Metadata         map[string]string      `json:"metadata,omitempty"`
}

func marshalProviderTokenSet(tokens ProviderTokenSet) ([]byte, error) {
	var idContext *ValidatedTokenContext
	if value, ok := tokens.IDContext(); ok {
		idContext = &value
	}
	var accessContext *ValidatedTokenContext
	if value, ok := tokens.AccessContext(); ok {
		accessContext = &value
	}
	return json.Marshal(providerTokenPayload{
		AccessToken:      tokens.AccessToken().Reveal(),
		RefreshToken:     tokens.RefreshToken().Reveal(),
		IDToken:          tokens.IDToken().Reveal(),
		TokenType:        tokens.TokenType(),
		Scopes:           tokens.Scopes(),
		AcquiredAt:       tokens.AcquiredAt(),
		AccessExpiresAt:  tokens.AccessExpiresAt(),
		RefreshExpiresAt: tokens.RefreshExpiresAt(),
		IDExpiresAt:      tokens.IDExpiresAt(),
		IDContext:        idContext,
		AccessContext:    accessContext,
		Metadata:         tokens.Metadata(),
	})
}

func unmarshalProviderTokenSet(payload []byte) (ProviderTokenSet, error) {
	if len(payload) == 0 || len(payload) > MaxProviderTokenPayloadBytes {
		return ProviderTokenSet{}, ErrProviderTokenEnvelope
	}
	var stored providerTokenPayload
	if err := json.Unmarshal(payload, &stored); err != nil {
		return ProviderTokenSet{}, ErrProviderTokenEnvelope
	}
	return NewProviderTokenSet(ProviderTokenSetInput{
		AccessToken:      NewSecret(stored.AccessToken),
		RefreshToken:     NewSecret(stored.RefreshToken),
		IDToken:          NewSecret(stored.IDToken),
		TokenType:        stored.TokenType,
		Scopes:           stored.Scopes,
		AcquiredAt:       stored.AcquiredAt,
		AccessExpiresAt:  stored.AccessExpiresAt,
		RefreshExpiresAt: stored.RefreshExpiresAt,
		IDExpiresAt:      stored.IDExpiresAt,
		IDContext:        stored.IDContext,
		AccessContext:    stored.AccessContext,
		Metadata:         stored.Metadata,
	})
}

var (
	_ ProviderSessionCreator  = (*ProviderSessionManager)(nil)
	_ ProviderSessionResolver = (*ProviderSessionManager)(nil)
	_ ProviderSessionRevoker  = (*ProviderSessionManager)(nil)
	_ UserTokenProvider       = (*ProviderSessionManager)(nil)
)
