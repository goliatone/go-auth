package auth

import (
	"fmt"
	"maps"
	"net/http"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	csfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-featuregate/gate"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-router/flash"
)

// MergeTemplateData ensures every render includes the latest template helpers
// (current user, CSRF helpers, etc.) merged with the provided view context.
// It evaluates helper closures that return strings or template.HTML so request-
// scoped helpers are always materialized before hitting the renderer.
func MergeTemplateData(ctx router.Context, data router.ViewContext) router.ViewContext {
	if data == nil {
		data = router.ViewContext{}
	}

	ensureTemplateHelpers(ctx)

	merged := router.ViewContext{}
	maps.Copy(merged, data)

	return merged
}

func ensureTemplateHelpers(ctx router.Context) {
	if helpers, ok := ctx.Locals(csfmw.DefaultTemplateHelpersKey).(map[string]any); ok && helpers != nil {
		return
	}

	helpers := TemplateHelpersWithRouter(ctx, TemplateUserKey)
	ctx.LocalsMerge(csfmw.DefaultTemplateHelpersKey, helpers)
}

type Middleware interface {
	Impersonate(c router.Context, identifier string) error
	ProtectedRoute(cfg Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc
}

func GetRouterSession(c router.Context, key string) (*SessionObject, error) {
	sessionData := c.Locals(key)
	if sessionData == nil {
		return nil, ErrUnableToFindSession
	}

	claims, ok := sessionData.(AuthClaims)
	if claims == nil || !ok {
		return nil, ErrUnableToDecodeSession
	}

	return sessionFromAuthClaims(claims)
}

func RegisterAuthRoutes[T any](app router.Router[T], opts ...AuthControllerOption) {

	controller := NewAuthController(opts...)

	app.
		Get(controller.Routes.Login,
			controller.LoginShow,
		).
		SetName("auth.sign-in.get")

	app.
		Post(
			controller.Routes.Login,
			// limitReq,
			controller.LoginPost,
		).
		SetName("auth.sign-in.post")

	app.Get(controller.Routes.Logout,
		controller.LogOut).
		SetName("auth.sign-out.get")

	app.Get(controller.Routes.Register,
		controller.RegistrationShow).
		SetName("auth.register.get")

	app.Post(controller.Routes.Register,
		controller.RegistrationCreate).
		SetName("auth.register.post")

	app.Get(controller.Routes.PasswordReset,
		controller.PasswordResetGet).
		SetName("auth.pwd-reset.get")

	app.Post(controller.Routes.PasswordReset,
		controller.PasswordResetPost).
		SetName("auth.pwd-reset.post")

	app.Get(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset),
		controller.PasswordResetForm).
		SetName("auth.pwd-reset-do.get")

	app.Post(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset),
		controller.PasswordResetExecute).
		SetName("auth.pwd-reset-do.post")
}

type AuthControllerRoutes struct {
	Login         string
	Logout        string
	Register      string
	PasswordReset string
}

type AuthControllerViews struct {
	Login         string
	Logout        string
	Register      string
	PasswordReset string
}

type AuthController struct {
	Debug            bool
	Logger           Logger
	LoggerProvider   LoggerProvider
	Repo             RepositoryManager
	Routes           *AuthControllerRoutes
	Views            *AuthControllerViews
	Auther           HTTPAuthenticator
	ErrorHandler     router.ErrorHandler
	RegisterRedirect string
	UseHashID        bool
	featureGate      gate.FeatureGate
	activity         ActivitySink
}

type AuthControllerOption func(*AuthController) *AuthController

func WithControllerLogger(logger Logger) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.LoggerProvider, ac.Logger = ResolveLogger("auth.controller", ac.LoggerProvider, logger)
		return ac
	}
}

func WithControllerLoggerProvider(provider LoggerProvider) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.LoggerProvider, ac.Logger = ResolveLogger("auth.controller", provider, ac.Logger)
		return ac
	}
}

func WithErrorHandler(errHandler router.ErrorHandler) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.ErrorHandler = errHandler
		return ac
	}
}

func WithAuthControllerRoutes(r *AuthControllerRoutes) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.Routes = r
		return ac
	}
}

func WithAuthControllerViews(v *AuthControllerViews) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.Views = v
		return ac
	}
}

func WithAuthControllerRedirect(r string) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.RegisterRedirect = r
		return ac
	}
}

func WithAuthControllerUseHashID(v bool) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.UseHashID = v
		return ac
	}
}

func WithAuthControllerActivitySink(sink ActivitySink) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.activity = normalizeActivitySink(sink)
		return ac
	}
}

func WithFeatureGate(featureGate gate.FeatureGate) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.featureGate = featureGate
		return ac
	}
}

func NewAuthController(opts ...AuthControllerOption) *AuthController {
	c := &AuthController{
		Logger:           defaultLogger(),
		ErrorHandler:     defaultErrHandler,
		RegisterRedirect: "/",
		activity:         noopActivitySink{},
		Routes: &AuthControllerRoutes{
			Login:         "/login",
			Logout:        "/logout",
			Register:      "/register",
			PasswordReset: "/password-reset",
		},
		Views: &AuthControllerViews{
			Login:         "login",
			Logout:        "logout",
			Register:      "register",
			PasswordReset: "password_reset",
		},
	}

	for _, opt := range opts {
		c = opt(c)
	}

	c.LoggerProvider, c.Logger = ResolveLogger("auth.controller", c.LoggerProvider, c.Logger)

	if c.Repo == nil {
		panic("Missing RepositoryManager in auth controller...")
	}

	if c.Auther == nil {
		panic("Missing HTTPAuthenticator in auth controller...")
	}

	return c
}

func (a *AuthController) handleControllerError(ctx router.Context, e error, view string, payload any) error {
	var err *errors.Error
	if !errors.As(e, &err) {
		err = errors.Wrap(e, errors.CategoryInternal, "An unexpected server error ocurred.").
			WithCode(errors.CodeInternal)
	}

	a.Logger.Error("Controller error", "details", print.MaybePrettyJSON(err), "stack", err.ErrorWithStack())

	statusCode := err.Code
	if statusCode == 0 {
		statusCode = http.StatusBadRequest
	}

	flashCtx := flash.WithError(ctx, MergeTemplateData(ctx, router.ViewContext{
		"error_message":  err.Message,
		"system_message": fmt.Sprintf("Error: %s", err.TextCode),
	}))

	viewCtx := MergeTemplateData(ctx, router.ViewContext{
		"record": payload,
	})

	switch err.Category {
	case errors.CategoryValidation, errors.CategoryBadInput, errors.CategoryConflict:
		viewCtx["validation"] = err.ValidationMap()

		if err.Category == errors.CategoryConflict {
			statusCode = http.StatusConflict
		}

		return flashCtx.Status(statusCode).Render(view, viewCtx)
	default:
		return a.ErrorHandler(flashCtx, err)
	}
}

func (a *AuthController) requireFeature(ctx router.Context, key string, disabledErr error, view string, payload any) error {
	err := requireFeatureGate(ctx.Context(), a.featureGate, key, disabledErr)
	if err != nil {
		return a.handleControllerError(ctx, err, view, payload)
	}

	return nil
}

func (a *AuthController) requirePasswordReset(ctx router.Context, allowFinalize bool, view string, payload any) error {
	err := requirePasswordResetGate(ctx.Context(), a.featureGate, allowFinalize)
	if err != nil {
		return a.handleControllerError(ctx, err, view, payload)
	}

	return nil
}

func (a *AuthController) LoginShow(ctx router.Context) error {
	return ctx.Render(a.Views.Login, MergeTemplateData(ctx, router.ViewContext{
		"errors": nil,
		"record": nil,
	}))
}

func (a *AuthController) WithLogger(l Logger) *AuthController {
	a.LoggerProvider, a.Logger = ResolveLogger("auth.controller", a.LoggerProvider, l)
	return a
}

// LoginRequest payload
type LoginRequest struct {
	Identifier string `form:"identifier" json:"identifier"`
	Password   string `form:"password" json:"password"`
	RememberMe bool   `form:"remember_me" json:"remember_me"`
}

// GetIdentifier returns the identifier
func (r LoginRequest) GetIdentifier() string {
	return r.Identifier
}

// GetPassword will return the password
func (r LoginRequest) GetPassword() string {
	return r.Password
}

// GetExtendedSession will return the password
func (r LoginRequest) GetExtendedSession() bool {
	return r.RememberMe
}

// Validate will run validation rules
func (r LoginRequest) Validate() *errors.Error {
	return errors.ValidateWithOzzo(func() error {
		return validation.ValidateStruct(&r,
			validation.Field(
				&r.Identifier,
				validation.Required,
				is.Email,
			),
			validation.Field(
				&r.Password,
				validation.Required,
			),
		)
	}, "Invalid login request payload")

}

func (a *AuthController) LoginPost(ctx router.Context) error {
	payload := new(LoginRequest)

	if err := ctx.Bind(payload); err != nil {
		bindErr := errors.Wrap(err, errors.CategoryBadInput, "Could not process request data").WithCode(http.StatusBadRequest)
		return a.handleControllerError(ctx, bindErr, a.Views.Login, payload)
	}

	if err := payload.Validate(); err != nil {
		return a.handleControllerError(ctx, err, a.Views.Login, payload)
	}

	if a.Debug {
		a.Logger.Debug("======= AUTH LOGIN ======")
		a.Logger.Debug("X-Request-ID", "id", ctx.Locals("requestid"))
		a.Logger.Debug(print.MaybeSecureJSON(payload))
		a.Logger.Debug("=========================")
	}

	if err := a.Auther.Login(ctx, payload); err != nil {
		var richErr *errors.Error
		if !errors.As(err, &richErr) {
			richErr = errors.Wrap(err, errors.CategoryAuth, "Authentication failed")
		}

		a.Logger.Error("Login failed", "error", richErr)

		return ctx.Status(http.StatusUnauthorized).Render(a.Views.Login, MergeTemplateData(ctx, router.ViewContext{
			"payload": payload,
			"errors": map[string]string{
				"authentication": richErr.Message,
			},
		}))
	}

	redirect := a.Auther.GetRedirect(ctx, "/")
	a.Logger.Info("redirecting", "url", redirect)
	return ctx.Redirect(redirect, router.StatusSeeOther)
}

func (a *AuthController) LogOut(ctx router.Context) error {
	a.Auther.Logout(ctx)
	return ctx.Redirect("/", router.StatusTemporaryRedirect)
}

func (a *AuthController) RegistrationShow(ctx router.Context) error {
	if err := a.requireFeature(ctx, gate.FeatureUsersSignup, ErrSignupDisabled, a.Views.Register, RegisterUserMessage{}); err != nil {
		return err
	}

	return ctx.Render(a.Views.Register, MergeTemplateData(ctx, router.ViewContext{
		"errors": map[string]string{},
		"record": RegisterUserMessage{},
	}))
}

// RegistrationCreatePayload is the form paylaod
type RegistrationCreatePayload struct {
	FirstName       string `form:"first_name" json:"first_name"`
	LastName        string `form:"last_name" json:"last_name"`
	Email           string `form:"email" json:"email"`
	Phone           string `form:"phone_number" json:"phone_number"`
	Password        string `form:"password" json:"password"`
	ConfirmPassword string `form:"confirm_password" json:"confirm_password"`
}

// Validate will validate the payload
func (r RegistrationCreatePayload) Validate() *errors.Error {
	return errors.ValidateWithOzzo(func() error {
		return validation.ValidateStruct(&r,
			validation.Field(&r.FirstName, validation.Required, validation.Length(1, 200)),
			validation.Field(&r.LastName, validation.Required, validation.Length(1, 200)),
			validation.Field(&r.Email, validation.Required, validation.Length(6, 100), is.Email),
			validation.Field(&r.Phone, validation.Length(10, 11), is.Digit),
			validation.Field(&r.Password, validation.Required, validation.Length(10, 100)),
			validation.Field(
				&r.ConfirmPassword,
				validation.Required,
				validation.Length(10, 100),
				validation.By(ValidateStringEquals(r.Password)),
			),
		)
	}, "Invalid registration payload")

}

func (a *AuthController) RegistrationCreate(ctx router.Context) error {
	if err := a.requireFeature(ctx, gate.FeatureUsersSignup, ErrSignupDisabled, a.Views.Register, nil); err != nil {
		return err
	}

	payload := new(RegistrationCreatePayload)

	if err := ctx.Bind(payload); err != nil {
		bindErr := errors.Wrap(err, errors.CategoryBadInput, "Could not process registration data.").WithCode(http.StatusBadRequest)
		return a.handleControllerError(ctx, bindErr, a.Views.Register, payload)
	}

	if err := payload.Validate(); err != nil {
		return a.handleControllerError(ctx, err, a.Views.Register, payload)
	}

	req := RegisterUserMessage{
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Email:     payload.Email,
		Phone:     payload.Phone,
		Password:  payload.Password,
		UseHashid: a.UseHashID,
	}

	registerUser := RegisterUserHandler{repo: a.Repo}
	if err := registerUser.Execute(ctx.Context(), req); err != nil {
		return a.handleControllerError(ctx, err, a.Views.Register, payload)
	}

	// on success we automatically log the user in
	signIn := LoginRequest{
		Identifier: payload.Email,
		Password:   payload.Password,
		RememberMe: true,
	}

	if err := a.Auther.Login(ctx, signIn); err != nil {
		flash.WithSuccess(ctx, MergeTemplateData(ctx, router.ViewContext{
			"system_message": "Registration successful! Please log in.",
		}))
		return ctx.Redirect(a.Routes.Login)
	}

	redirect := a.RegisterRedirect
	if redirect == "" {
		redirect = "/"
	}

	return flash.WithSuccess(ctx, MergeTemplateData(ctx, router.ViewContext{
		"system_message": "Successful user registration",
	})).Redirect(redirect, http.StatusSeeOther)
}

const (
	stageKey   = "stage"
	sessionKey = "session"
	emailKey   = "email"
)

func (a *AuthController) PasswordResetGet(ctx router.Context) error {
	if err := a.requirePasswordReset(ctx, false, a.Views.PasswordReset, nil); err != nil {
		return err
	}

	return ctx.Render(a.Views.PasswordReset, MergeTemplateData(ctx, router.ViewContext{
		"errors": nil,
		"reset": map[string]string{
			stageKey: ResetInit,
		},
	}))
}

// PasswordResetRequestPayload holds values for password reset
type PasswordResetRequestPayload struct {
	Email string `form:"email" json:"email"`
	Stage string `form:"stage" json:"stage"`
}

// Validate will validate the payload
func (r PasswordResetRequestPayload) Validate() *errors.Error {
	return errors.ValidateWithOzzo(func() error {
		return validation.ValidateStruct(&r,
			validation.Field(
				&r.Stage,
				validation.Required,
				validation.In(
					ResetInit,
				),
			),
			validation.Field(
				&r.Email,
				validation.Required,
				is.Email,
			),
		)
	}, "Invalid password reset ")

}

func (a *AuthController) PasswordResetPost(ctx router.Context) error {
	if err := a.requirePasswordReset(ctx, false, a.Views.PasswordReset, nil); err != nil {
		return err
	}

	payload := new(PasswordResetRequestPayload)

	if err := ctx.Bind(payload); err != nil {
		bindErr := errors.Wrap(err, errors.CategoryBadInput, "Could not process request.").WithCode(http.StatusBadRequest)
		return a.handleControllerError(ctx, bindErr, a.Views.PasswordReset, payload)
	}

	if err := payload.Validate(); err != nil {
		return a.handleControllerError(ctx, err, a.Views.PasswordReset, payload)
	}

	var res *InitializePasswordResetResponse
	req := InitializePasswordResetMessage{
		Stage: payload.Stage,
		Email: payload.Email,
		OnResponse: func(resp *InitializePasswordResetResponse) {
			res = resp
		},
	}

	initPwdReset := InitializePasswordResetHandler{repo: a.Repo}
	if err := initPwdReset.Execute(ctx.Context(), req); err != nil {
		return a.handleControllerError(ctx, err, a.Views.PasswordReset, payload)
	}

	if a.Debug {
		a.Logger.Debug("Password reset response", "response", print.MaybePrettyJSON(res))
	}

	if res.Success && res.Stage == AccountVerification {
		if res.Reset == nil {
			return flash.WithSuccess(ctx, MergeTemplateData(ctx, router.ViewContext{
				"system_message": "If an account with that email exists, a password reset link has been sent.",
			})).Redirect(a.Routes.Login)
		}

		sessionID := res.Reset.ID.String()
		if sessionID == "" {
			return flash.WithSuccess(ctx, MergeTemplateData(ctx, router.ViewContext{
				"system_message": "If an account with that email exists, a password reset link has been sent.",
			})).Redirect(a.Routes.Login)
		}

		email := res.Reset.Email
		if email == "" {
			email = req.Email
		}

		return ctx.Render(a.Views.PasswordReset, MergeTemplateData(ctx, router.ViewContext{
			"reset": map[string]string{
				stageKey:   AccountVerification,
				sessionKey: sessionID,
				emailKey:   email,
			},
		}))
	}

	// this is unlikely if command works OK, just a safe fallback
	return flash.WithSuccess(ctx, MergeTemplateData(ctx, router.ViewContext{
		"system_message": "If an account with that email exists, a password reset link has been sent.",
	})).Redirect(a.Routes.Login)
}

func (a *AuthController) PasswordResetForm(ctx router.Context) error {
	if err := a.requirePasswordReset(ctx, true, a.Views.PasswordReset, nil); err != nil {
		return err
	}

	sessionID := ctx.Param("uuid", "")

	errors := map[string]string{}

	var resp *AccountVerificationResponse
	input := AccountVerificationMesage{
		Session: sessionID,
		OnResponse: func(a *AccountVerificationResponse) {
			resp = a
		},
	}

	accountVerify := AccountVerificationHandler{repo: a.Repo}

	if err := accountVerify.Execute(ctx.Context(), input); err != nil {
		a.Logger.Error("verification error", "error", err)
		errors["verification"] = err.Error()
		return ctx.Render(a.Views.PasswordReset, MergeTemplateData(ctx, router.ViewContext{
			"errors": errors,
			"reset": map[string]string{
				stageKey:   ChangingPassword,
				sessionKey: sessionID,
				emailKey:   "",
			},
		}))
	}

	if a.Debug {
		a.Logger.Debug("======= Password Reset ======")
		a.Logger.Debug(print.MaybePrettyJSON(resp))
		a.Logger.Debug("=============================")
	}

	currentStage := ChangingPassword
	if resp.Expired || !resp.Found {
		currentStage = ResetUnknown
	}

	return ctx.Render(a.Views.PasswordReset, MergeTemplateData(ctx, router.ViewContext{
		"errors": errors,
		"reset": map[string]string{
			sessionKey: sessionID,
			stageKey:   currentStage,
		},
	}))
}

// PasswordResetVerifyPayload holds values for password reset
type PasswordResetVerifyPayload struct {
	Stage           string `form:"stage" json:"stage"`
	Password        string `form:"password" json:"password"`
	ConfirmPassword string `form:"confirm_password" json:"confirm_password"`
}

// Validate will validate the payload
func (r PasswordResetVerifyPayload) Validate() *errors.Error {
	return errors.ValidateWithOzzo(func() error {
		return validation.ValidateStruct(&r,
			validation.Field(
				&r.Stage,
				validation.Required,
				validation.In(
					ChangingPassword,
				),
			),
			validation.Field(
				&r.Password,
				validation.Required,
				validation.Length(10, 100),
			),
			validation.Field(
				&r.ConfirmPassword,
				validation.Required,
				validation.Length(10, 100),
				validation.By(ValidateStringEquals(r.Password)),
			),
		)
	}, "Invalid password reset payload")
}

func (a *AuthController) PasswordResetExecute(ctx router.Context) error {
	if err := a.requirePasswordReset(ctx, true, a.Views.PasswordReset, nil); err != nil {
		return err
	}

	sessionID := ctx.Param("uuid")
	payload := new(PasswordResetVerifyPayload)

	if err := ctx.Bind(payload); err != nil {
		bindErr := errors.Wrap(err, errors.CategoryBadInput, "Could not process request.").WithCode(http.StatusBadRequest)
		return a.handleControllerError(ctx, bindErr, a.Views.PasswordReset, payload)
	}

	if err := payload.Validate(); err != nil {
		return a.handleControllerError(ctx, err, a.Views.PasswordReset, payload)
	}

	input := FinalizePasswordResetMesasge{
		Session:  sessionID,
		Password: payload.Password,
	}

	resetLogger := a.Logger
	if a.LoggerProvider != nil {
		resetLogger = a.LoggerProvider.GetLogger("auth.password_reset")
	}

	finalizePwdReset := NewFinalizePasswordResetHandler(a.Repo).
		WithActivitySink(a.activity).
		WithLogger(resetLogger)
	if err := finalizePwdReset.Execute(ctx.Context(), input); err != nil {
		return a.handleControllerError(ctx, err, a.Views.PasswordReset, payload)
	}

	return ctx.Render(a.Views.PasswordReset, MergeTemplateData(ctx, router.ViewContext{
		"reset": router.ViewContext{
			stageKey:   ChangeFinalized,
			sessionKey: sessionID,
		},
	}))
}

// ValidateStringEquals will check that both values match
func ValidateStringEquals(str string) validation.RuleFunc {
	return func(value any) error {
		s, _ := value.(string)
		if s != str {
			return errors.New("values must match", errors.CategoryValidation)
		}
		return nil
	}
}

func defaultErrHandler(c router.Context, err error) error {
	var richErr *errors.Error
	if !errors.As(err, &richErr) {
		richErr = errors.Wrap(err, errors.CategoryInternal, "An unexpected server error occurred.").
			WithCode(errors.CodeInternal)
	}

	statusCode := richErr.Code
	if statusCode == 0 {
		statusCode = http.StatusInternalServerError
	}

	viewCtx := router.ViewContext{
		"message": richErr.Message,
	}
	if richErr.TextCode != "" {
		viewCtx["system_message"] = fmt.Sprintf("Error: %s", richErr.TextCode)
	}

	return c.Status(statusCode).Render("errors/500", viewCtx)
}
