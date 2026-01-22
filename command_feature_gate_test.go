package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-featuregate/gate"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubFeatureGate struct {
	enabled map[string]bool
	calls   []string
	err     error
}

func (s *stubFeatureGate) Enabled(ctx context.Context, key string, opts ...gate.ResolveOption) (bool, error) {
	s.calls = append(s.calls, key)
	if s.err != nil {
		return false, s.err
	}
	if s.enabled == nil {
		return true, nil
	}
	enabled, ok := s.enabled[key]
	if !ok {
		return true, nil
	}
	return enabled, nil
}

func TestRegisterUserHandlerFeatureGateDeniesSignup(t *testing.T) {
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersSignup: false,
		},
	}

	handler := auth.NewRegisterUserHandler(nil).WithFeatureGate(stubGate)

	err := handler.Execute(context.Background(), auth.RegisterUserMessage{})
	require.ErrorIs(t, err, auth.ErrSignupDisabled)
	require.Equal(t, []string{gate.FeatureUsersSignup}, stubGate.calls)
}

func TestInitializePasswordResetHandlerFeatureGateDenies(t *testing.T) {
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersPasswordReset: false,
		},
	}

	handler := auth.NewInitializePasswordResetHandler(nil).WithFeatureGate(stubGate)

	err := handler.Execute(context.Background(), auth.InitializePasswordResetMessage{})
	require.ErrorIs(t, err, auth.ErrPasswordResetDisabled)
	require.Equal(t, []string{gate.FeatureUsersPasswordReset}, stubGate.calls)
}

func TestFinalizePasswordResetHandlerFeatureGateDenies(t *testing.T) {
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersPasswordReset:         false,
			gate.FeatureUsersPasswordResetFinalize: false,
		},
	}

	handler := auth.NewFinalizePasswordResetHandler(&MockRepositoryManager{}).WithFeatureGate(stubGate)

	err := handler.Execute(context.Background(), auth.FinalizePasswordResetMesasge{
		Session:  "session-token",
		Password: "password12345",
	})
	require.ErrorIs(t, err, auth.ErrPasswordResetDisabled)
	require.Equal(t, []string{
		gate.FeatureUsersPasswordReset,
		gate.FeatureUsersPasswordResetFinalize,
	}, stubGate.calls)
}

func TestFinalizePasswordResetHandlerAllowsFinalizeOverride(t *testing.T) {
	stubGate := &stubFeatureGate{
		enabled: map[string]bool{
			gate.FeatureUsersPasswordReset:         false,
			gate.FeatureUsersPasswordResetFinalize: true,
		},
	}

	repo := &MockRepositoryManager{}
	repo.On("RunInTx", mock.Anything, mock.Anything, mock.Anything).
		Return(errors.New("tx failed")).
		Once()

	handler := auth.NewFinalizePasswordResetHandler(repo).WithFeatureGate(stubGate)

	err := handler.Execute(context.Background(), auth.FinalizePasswordResetMesasge{
		Session:  "session-token",
		Password: "password12345",
	})
	require.Error(t, err)
	require.NotEqual(t, auth.ErrPasswordResetDisabled, err)
	require.Equal(t, []string{
		gate.FeatureUsersPasswordReset,
		gate.FeatureUsersPasswordResetFinalize,
	}, stubGate.calls)
	repo.AssertExpectations(t)
}
