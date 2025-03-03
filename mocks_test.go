package auth_test

import (
	"context"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-router"
	"github.com/stretchr/testify/mock"
)

// MockAuthenticator implements auth.Authenticator
type MockAuthenticator struct {
	mock.Mock
}

func (m *MockAuthenticator) Login(ctx context.Context, identifier, password string) (string, error) {
	args := m.Called(ctx, identifier, password)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) Impersonate(ctx context.Context, identifier string) (string, error) {
	args := m.Called(ctx, identifier)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) SessionFromToken(token string) (auth.Session, error) {
	args := m.Called(token)
	return args.Get(0).(auth.Session), args.Error(1)
}

func (m *MockAuthenticator) IdentityFromSession(ctx context.Context, session auth.Session) (auth.Identity, error) {
	args := m.Called(ctx, session)
	return args.Get(0).(auth.Identity), args.Error(1)
}

// MockLoginPayload implements auth.LoginPayload
type MockLoginPayload struct {
	Identifier      string
	Password        string
	ExtendedSession bool
}

func (m MockLoginPayload) GetIdentifier() string {
	return m.Identifier
}

func (m MockLoginPayload) GetPassword() string {
	return m.Password
}

func (m MockLoginPayload) GetExtendedSession() bool {
	return m.ExtendedSession
}

// MockSession mocks the router.Context
type MockContext struct {
	mock.Mock
	NextCalled bool
}

func (m *MockContext) Next() error {
	m.NextCalled = true
	return nil
}

func (m *MockContext) Context() context.Context {
	args := m.Called()
	c, ok := args.Get(0).(context.Context)
	if !ok {
		panic("arg needs to be context.Context")
	}
	return c
}

func (m *MockContext) SetContext(ctx context.Context) {
	m.Called(ctx)
}

func (m *MockContext) Path() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockContext) Method() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockContext) Body() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockContext) Status(code int) router.Context {
	m.Called(code)
	return m
}

func (m *MockContext) SendString(s string) error {
	args := m.Called(s)
	return args.Error(0)
}

func (m *MockContext) Send(b []byte) error {
	args := m.Called(b)
	return args.Error(0)
}

func (m *MockContext) JSON(code int, val any) error {
	args := m.Called(code, val)
	return args.Error(0)
}

func (m *MockContext) NoContent(code int) error {
	args := m.Called(code)
	return args.Error(0)
}

func (m *MockContext) Render(name string, bind any, layout ...string) error {
	if len(layout) > 0 {
		args := m.Called(name, bind, layout[0])
		return args.Error(0)
	}
	args := m.Called(name, bind)
	return args.Error(0)
}

func (m *MockContext) Redirect(path string, status ...int) error {
	if len(status) > 0 {
		args := m.Called(path, status)
		return args.Error(0)
	}
	args := m.Called(path)
	return args.Error(0)
}

func (m *MockContext) RedirectToRoute(name string, data router.ViewContext, status ...int) error {
	if len(status) > 0 {
		args := m.Called(name, data, status[0])
		return args.Error(0)
	}
	args := m.Called(name, data)
	return args.Error(0)
}

func (m *MockContext) RedirectBack(fallback string, status ...int) error {
	if len(status) > 0 {
		args := m.Called(fallback, status)
		return args.Error(0)
	}
	args := m.Called(fallback)
	return args.Error(0)
}

func (m *MockContext) SetHeader(key, val string) router.Context {
	m.Called(key, val)
	return m
}

func (m *MockContext) Header(key string) string {
	args := m.Called(key)
	return args.String(0)
}

func (m *MockContext) Get(key string, defaultValue any) any {
	args := m.Called(key, defaultValue)
	return args.Get(0)
}

func (m *MockContext) GetBool(key string, defaultValue bool) bool {
	args := m.Called(key, defaultValue)
	return args.Bool(0)
}

func (m *MockContext) GetInt(key string, def int) int {
	args := m.Called(key, def)
	return args.Int(0)
}

func (m *MockContext) Set(key string, val any) {
	m.Called(key, val)
}

func (m *MockContext) Bind(i any) error {
	args := m.Called(i)
	return args.Error(0)
}

func (m *MockContext) BindJSON(i any) error {
	args := m.Called(i)
	return args.Error(0)
}

func (m *MockContext) BindXML(i any) error {
	args := m.Called(i)
	return args.Error(0)
}

func (m *MockContext) BindQuery(i any) error {
	args := m.Called(i)
	return args.Error(0)
}

func (m *MockContext) CookieParser(i any) error {
	args := m.Called(i)
	return args.Error(0)
}

func (m *MockContext) Cookie(cookie *router.Cookie) {
	m.Called(cookie)
}

func (m *MockContext) Cookies(key string, defaultValue ...string) string {
	if len(defaultValue) > 0 {
		args := m.Called(key, defaultValue[0])
		return args.String(0)
	}
	args := m.Called(key)
	return args.String(0)
}

func (m *MockContext) Param(key string, defaultValue ...string) string {
	if len(defaultValue) > 0 {
		args := m.Called(key, defaultValue[0])
		return args.String(0)
	}
	args := m.Called(key)
	return args.String(0)
}

func (m *MockContext) ParamsInt(key string, defaultValue int) int {
	args := m.Called(key, defaultValue)
	return args.Int(0)
}

func (m *MockContext) Query(key string, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockContext) QueryInt(key string, defaultValue int) int {
	args := m.Called(key, defaultValue)
	return args.Int(0)
}

func (m *MockContext) Queries() map[string]string {
	args := m.Called()
	return args.Get(0).(map[string]string)
}

func (m *MockContext) GetString(key string, defaultValue string) string {
	args := m.Called(key, defaultValue)
	return args.String(0)
}

func (m *MockContext) Locals(key any, value ...any) any {
	if len(value) > 0 {
		m.Called(key, value[0])
		return nil
	}
	args := m.Called(key)
	return args.Get(0)
}

func (m *MockContext) OriginalURL() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockContext) OnNext(callback func() error) {
	m.Called(callback)
}

func (m *MockContext) Referer() string {
	args := m.Called()
	return args.String(0)
}
