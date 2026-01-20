package auth

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// UserRole is the user's role
type UserRole string

const (
	// RoleGuest is an guest role (ie. view)
	RoleGuest UserRole = "guest"
	// RoleMember us a member (i.e. view, edit)
	RoleMember UserRole = "member"
	// RoleAdmin is an admin role (i.e. view, edit, create)
	RoleAdmin UserRole = "admin"
	// RoleOwner is an admin role (i.e. view, edit, create, delete)
	RoleOwner UserRole = "owner"
)

// UserStatus represents lifecycle states for a user account
type UserStatus string

const (
	// UserStatusPending indicates the account exists but is not yet active
	UserStatusPending UserStatus = "pending"
	// UserStatusActive represents a fully active account
	UserStatusActive UserStatus = "active"
	// UserStatusSuspended indicates temporary suspension
	UserStatusSuspended UserStatus = "suspended"
	// UserStatusDisabled indicates manual disablement with no path back to active except admin intervention
	UserStatusDisabled UserStatus = "disabled"
	// UserStatusArchived signals the record should be treated as deleted/read-only
	UserStatusArchived UserStatus = "archived"
)

// User is the user model
type User struct {
	bun.BaseModel      `bun:"table:users,alias:usr"`
	ID                 uuid.UUID      `bun:"id,pk,nullzero,type:uuid" json:"id,omitempty"`
	Role               UserRole       `bun:"user_role,notnull" json:"user_role,omitempty"`
	Status             UserStatus     `bun:"status,notnull,default:'active'" json:"status,omitempty"`
	FirstName          string         `bun:"first_name,notnull" json:"first_name,omitempty"`
	LastName           string         `bun:"last_name,notnull" json:"last_name,omitempty"`
	Username           string         `bun:"username,notnull,unique" json:"username,omitempty"`
	ProfilePicture     string         `bun:"profile_picture" json:"profile_picture,omitempty"`
	Email              string         `bun:"email,notnull,unique" json:"email,omitempty"`
	ExternalID         string         `bun:"external_id" json:"external_id,omitempty"`
	ExternalIDProvider string         `bun:"external_id_provider" json:"external_id_provider,omitempty"`
	Phone              string         `bun:"phone_number" json:"phone_number,omitempty"`
	PasswordHash       string         `bun:"password_hash" json:"password_hash,omitempty"`
	EmailValidated     bool           `bun:"is_email_verified" json:"is_email_verified,omitempty"`
	LoginAttempts      int            `bun:"login_attempts" json:"login_attempts,omitempty"`
	LoginAttemptAt     *time.Time     `bun:"login_attempt_at" json:"login_attempt_at,omitempty"`
	LoggedInAt         *time.Time     `bun:"loggedin_at" json:"loggedin_at,omitempty"`
	SuspendedAt        *time.Time     `bun:"suspended_at,nullzero" json:"suspended_at,omitempty"`
	Metadata           map[string]any `bun:"metadata" json:"metadata,omitempty"`
	ResetedAt          *time.Time     `bun:"reseted_at,nullzero" json:"reseted_at,omitempty"`
	CreatedAt          *time.Time     `bun:"created_at,nullzero,default:current_timestamp" json:"created_at,omitempty"`
	UpdatedAt          *time.Time     `bun:"updated_at,nullzero,default:current_timestamp" json:"updated_at,omitempty"`
	DeletedAt          *time.Time     `bun:"deleted_at,soft_delete,nullzero" json:"deleted_at,omitempty"`
}

// AddMetadata will append information to a metadata attribute
// TODO: make a trigger to merge metadata in database!
// https://stackoverflow.com/a/42954907/125083
func (u *User) AddMetadata(key string, val any) *User {
	if u.Metadata == nil {
		u.Metadata = make(map[string]any)
	}
	u.Metadata[key] = val
	return u
}

// EnsureStatus sets a default status when empty to keep DB constraints satisfied.
func (u *User) EnsureStatus() *User {
	if u == nil {
		return u
	}
	if u.Status == "" {
		u.Status = UserStatusActive
	}
	return u
}

// HasStatus reports whether the user is currently in the provided status.
func (u *User) HasStatus(status UserStatus) bool {
	if u == nil {
		return false
	}
	if status == "" {
		return false
	}
	return u.Status == status
}

// IsActive returns true when the user is marked active.
func (u *User) IsActive() bool {
	return u.HasStatus(UserStatusActive)
}

// IsPending returns true when the user is pending activation.
func (u *User) IsPending() bool {
	return u.HasStatus(UserStatusPending)
}

// IsSuspended returns true when the user is suspended.
func (u *User) IsSuspended() bool {
	return u.HasStatus(UserStatusSuspended)
}

// IsDisabled returns true when the user is disabled.
func (u *User) IsDisabled() bool {
	return u.HasStatus(UserStatusDisabled)
}

// IsArchived returns true when the user is archived.
func (u *User) IsArchived() bool {
	return u.HasStatus(UserStatusArchived)
}

// PasswordResetStep step on password reset
type PasswordResetStep = string

const (
	// ResetUnknown is the unknown status
	ResetUnknown PasswordResetStep = "unknown"
	// ResetInit is the initial step
	ResetInit PasswordResetStep = "show-reset"
	//AccountVerification notifiction sent
	AccountVerification PasswordResetStep = "email-sent"
	// ChangingPassword user will change password
	ChangingPassword PasswordResetStep = "change-password"
	// ChangeFinalized processing change
	ChangeFinalized PasswordResetStep = "password-changed"
)

const (
	// ResetUnknownStatus is the unknown status
	ResetUnknownStatus = "unknown"
	// ResetRequestedStatus is the requested status
	ResetRequestedStatus = "requested"
	// ResetExpiredStatus is the expired status
	ResetExpiredStatus = "expired"
	// ResetChangedStatus is the changed status
	ResetChangedStatus = "changed"
)

// PasswordReset is the user model
type PasswordReset struct {
	bun.BaseModel `bun:"table:password_reset,alias:pwdr"`
	ID            uuid.UUID  `bun:"id,pk,nullzero,type:uuid" json:"id,omitempty"`
	UserID        *uuid.UUID `bun:"user_id,notnull" json:"user_id,omitempty"`
	User          *User      `bun:"rel:has-one,join:user_id=id" json:"user,omitempty"`
	Status        string     `bun:"status,notnull" json:"status,omitempty"`
	Email         string     `bun:"email,notnull" json:"email,omitempty"`
	DeletedAt     *time.Time `bun:"deleted_at,soft_delete,nullzero" json:"deleted_at,omitempty"`
	ResetedAt     *time.Time `bun:"reseted_at,nullzero" json:"reseted_at,omitempty"`
	CreatedAt     *time.Time `bun:"created_at,nullzero,default:current_timestamp" json:"created_at,omitempty"`
	UpdatedAt     *time.Time `bun:"updated_at,nullzero,default:current_timestamp" json:"updated_at,omitempty"`
}

// MarkPasswordAsReseted will create a new instance
func MarkPasswordAsReseted(id uuid.UUID) *PasswordReset {
	r := &PasswordReset{}
	r.ID = id
	r.Status = ResetChangedStatus
	n := time.Now()
	r.ResetedAt = &n
	return r
}
