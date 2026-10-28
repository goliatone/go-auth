package auth

import (
	"fmt"
	"io"
	"maps"
	"reflect"
	"time"

	"github.com/goliatone/go-auth/middleware/jwtware"
	"github.com/goliatone/go-router"
)

// NewTemplateViews wraps a configured engine with an opt-in auth view boundary.
// Claims in plain render maps/slices expose identity and permission checks, not
// raw JWT metadata or extension methods. Request locals and context are untouched.
// Configure engine-specific helpers/extensions before wrapping. Nil stays nil.
func NewTemplateViews(views router.Views) router.Views {
	if views == nil {
		return nil
	}
	return &authTemplateViews{Views: views}
}

type authTemplateViews struct{ router.Views }

func (v *authTemplateViews) Render(w io.Writer, name string, bind any, layouts ...string) error {
	data, err := authViewData(bind, 0)
	if err != nil {
		return err
	}
	return v.Views.Render(w, name, data, layouts...)
}

func authViewData(value any, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("auth views: cyclic or excessively deep view data")
	}
	switch value := value.(type) {
	case jwtware.AuthClaims:
		if nilViewClaims(value) {
			return nil, nil
		}
		view := templateClaimsView{
			UID: value.UserID(), UserRole: value.Role(),
			subject: value.Subject, userID: value.UserID, role: value.Role,
			canRead: value.CanRead, canEdit: value.CanEdit,
			canCreate: value.CanCreate, canDelete: value.CanDelete,
			hasRole: value.HasRole, isAtLeast: value.IsAtLeast,
		}
		if timed, ok := value.(interface{ Expires() time.Time }); ok {
			view.expires = timed.Expires
		}
		if timed, ok := value.(interface{ IssuedAt() time.Time }); ok {
			view.issuedAt = timed.IssuedAt
		}
		if carrier, ok := value.(resourceRoleCarrier); ok {
			view.Resources = maps.Clone(carrier.ResourceRoles())
		}
		return view, nil
	case router.ViewContext:
		return authViewData(map[string]any(value), depth)
	case map[string]any:
		if value == nil {
			return value, nil
		}
		out := make(map[string]any, len(value))
		for key, item := range value {
			adapted, err := authViewData(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = adapted
		}
		return out, nil
	case []any:
		if value == nil {
			return value, nil
		}
		out := make([]any, len(value))
		for i, item := range value {
			adapted, err := authViewData(item, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = adapted
		}
		return out, nil
	default:
		// The underlying renderer still validates foreign values, arbitrary
		// models and helpers. Never serialize them to evade that boundary.
		return value, nil
	}
}

func nilViewClaims(claims jwtware.AuthClaims) bool {
	v := reflect.ValueOf(claims)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// This intentionally does not embed claims: promoted extension methods could
// expose dynamic values. All exported methods have closed, renderable results.
// Bound methods preserve custom policy without a traversable raw claims field.
// Public display fields and role maps are copies, never authentication state.
type templateClaimsView struct {
	UID       string
	UserRole  string
	Resources map[string]string

	subject, userID, role                  func() string
	canRead, canEdit, canCreate, canDelete func(string) bool
	hasRole, isAtLeast                     func(string) bool
	expires, issuedAt                      func() time.Time
}

var _ AuthClaims = templateClaimsView{}

func (v templateClaimsView) Subject() string                  { return v.subject() }
func (v templateClaimsView) UserID() string                   { return v.userID() }
func (v templateClaimsView) Role() string                     { return v.role() }
func (v templateClaimsView) CanRead(resource string) bool     { return v.canRead(resource) }
func (v templateClaimsView) CanEdit(resource string) bool     { return v.canEdit(resource) }
func (v templateClaimsView) CanCreate(resource string) bool   { return v.canCreate(resource) }
func (v templateClaimsView) CanDelete(resource string) bool   { return v.canDelete(resource) }
func (v templateClaimsView) HasRole(role string) bool         { return v.hasRole(role) }
func (v templateClaimsView) IsAtLeast(role string) bool       { return v.isAtLeast(role) }
func (v templateClaimsView) ResourceRoles() map[string]string { return maps.Clone(v.Resources) }
func (v templateClaimsView) Expires() time.Time {
	if v.expires != nil {
		return v.expires()
	}
	return time.Time{}
}
func (v templateClaimsView) IssuedAt() time.Time {
	if v.issuedAt != nil {
		return v.issuedAt()
	}
	return time.Time{}
}
