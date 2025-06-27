package auth

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-router/flash"
)

type Middleware interface {
	Impersonate(c router.Context, identifier string) error
	ProtectedRoute(cfg Config, errorHandler func(router.Context, error) error) router.MiddlewareFunc
}

func GetRouterSession(c router.Context, key string) (*SessionObject, error) {
	cookie := c.Locals(key)
	if cookie == nil {
		return nil, ErrUnableToFindSession
	}

	user, ok := cookie.(*jwt.Token)
	if user == nil || !ok {
		return nil, ErrUnableToDecodeSession
	}

	claims, ok := user.Claims.(jwt.MapClaims)
	if claims == nil || !ok {
		return nil, ErrUnableToMapClaims
	}

	return sessionFromClaims(claims)
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
	Repo             RepositoryManager
	Routes           *AuthControllerRoutes
	Views            *AuthControllerViews
	Auther           HTTPAuthenticator
	ErrorHandler     router.ErrorHandler
	RegisterRedirect string
	UseHashID        bool
}

type AuthControllerOption func(*AuthController) *AuthController

func WithControllerLogger(logger Logger) AuthControllerOption {
	return func(ac *AuthController) *AuthController {
		ac.Logger = logger
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

func NewAuthController(opts ...AuthControllerOption) *AuthController {
	c := &AuthController{
		Logger:           defLogger{},
		ErrorHandler:     defaultErrHandler,
		RegisterRedirect: "/",
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

	if c.Repo == nil {
		panic("Missing RepositoryManager in auth controller...")
	}

	if c.Auther == nil {
		panic("Missing HTTPAuthenticator in auth controller...")
	}

	return c
}

func (a *AuthController) LoginShow(ctx router.Context) error {
	return ctx.Render(a.Views.Login, router.ViewContext{
		"errors": nil,
		"record": nil,
	})
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
	errors := map[string]string{}

	reqID := ctx.Header("X-Request-ID")
	a.Logger.Debug("--- Login Post: ", "request-id", reqID)

	if err := ctx.Bind(payload); err != nil {
		a.Logger.Error("Login post bind error", err)
		return a.ErrorHandler(ctx, err)
	}

	if err := payload.Validate(); err != nil {
		a.Logger.Error("Login post validation error", err)
		fmt.Println(err.ValidationMap())
		fmt.Println(print.MaybePrettyJSON(err.ValidationMap()))

		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Message,
			"system_message": "Error validating payload",
		}).Render(a.Views.Login, router.ViewContext{
			"record":     payload,
			"validation": err.ValidationMap(),
		})
	}

	if a.Debug {
		a.Logger.Debug("======= AUTH LOGIN ======")
		a.Logger.Debug("X-Request-ID", "id", ctx.Locals("requestid"))
		a.Logger.Debug(print.MaybeSecureJSON(payload))
		a.Logger.Debug("=========================")
	}

	if err := a.Auther.Login(ctx, payload); err != nil {
		errors["authentication"] = "Authentication Error"
		return ctx.Render(a.Views.Login, router.ViewContext{
			"errors":  errors,
			"payload": payload,
		})
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
	return ctx.Render(a.Views.Register, router.ViewContext{
		"errors": map[string]string{},
		"record": RegisterUserMessage{},
	})
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
	payload := new(RegistrationCreatePayload)

	if err := ctx.Bind(payload); err != nil {
		errors := map[string]string{}
		errors["form"] = "Failed to parse form"
		a.Logger.Error("register user parse payload: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error parsing body",
		}).Status(fiber.StatusBadRequest).Render(a.Views.Register, router.ViewContext{
			"errors": errors,
			"record": payload,
		})
	}

	if err := payload.Validate(); err != nil {
		a.Logger.Error("register user validate payload: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Message,
			"system_message": "Error validating payload",
		}).Render(a.Views.Register, router.ViewContext{
			"record":     payload,
			"validation": err.ValidationMap(),
		})
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
		a.Logger.Error("order get error: ", "error", err)

		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error validating payload",
		}).Render(a.Views.Register, router.ViewContext{
			"record": payload,
			"errors": []string{err.Error()},
		})
	}

	signIn := LoginRequest{
		Identifier: payload.Email,
		Password:   payload.Password,
		RememberMe: true,
	}

	if err := a.Auther.Login(ctx, signIn); err != nil {
		return ctx.Render(a.Views.Login, router.ViewContext{
			"errors": map[string]string{
				"authentication": "Authentication Error",
			},
			"payload": payload,
		})
	}

	redirect := "/"
	if a.RegisterRedirect != "" {
		redirect = a.RegisterRedirect
	}

	return flash.WithSuccess(ctx, router.ViewContext{
		"system_message": "Successful user registration",
	}).Redirect(redirect, fiber.StatusSeeOther)
}

const (
	stageKey   = "stage"
	sessionKey = "session"
	emailKey   = "email"
)

func (a *AuthController) PasswordResetGet(ctx router.Context) error {
	return ctx.Render(a.Views.PasswordReset, router.ViewContext{
		"errors": nil,
		"reset": map[string]string{
			stageKey: ResetInit,
		},
	})
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
	errors := map[string]string{}
	payload := new(PasswordResetRequestPayload)

	if err := ctx.Bind(payload); err != nil {
		errors["form"] = "Failed to parse form"
		a.Logger.Error("register user parse payload: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error parsing body",
		}).Status(fiber.StatusBadRequest).Render(a.Views.PasswordReset, router.ViewContext{
			"errors": errors,
			"record": payload,
		})
	}

	if err := payload.Validate(); err != nil {
		a.Logger.Error("register user validate payload: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Message,
			"system_message": "Error validating payload",
		}).Render(a.Views.PasswordReset, router.ViewContext{
			"record":     payload,
			"validation": err.ValidationMap(),
		})
	}

	var res *InitializePasswordResetResponse

	req := InitializePasswordResetMessage{
		Stage: payload.Stage,
		Email: payload.Email,
		OnResponse: func(resp *InitializePasswordResetResponse) {
			res = resp
		},
	}

	initPwdReset := InitializePasswordResetHandler{
		repo: a.Repo,
	}

	if err := initPwdReset.Execute(ctx.Context(), req); err != nil {
		a.Logger.Error("order get error: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error validating payload",
		}).Render(a.Views.PasswordReset, router.ViewContext{
			"record": payload,
			"errors": []string{err.Error()},
		})
	}

	if a.Debug {
		a.Logger.Debug("================")
		a.Logger.Debug(print.MaybePrettyJSON(res))
		a.Logger.Debug("================")
	}

	redirect := "/"

	if res.Success && res.Stage == AccountVerification {
		return ctx.Render(a.Views.PasswordReset, router.ViewContext{
			"errors": errors,
			"reset": map[string]string{
				stageKey:   AccountVerification,
				sessionKey: req.Session,
				emailKey:   req.Email,
			},
		})
	}

	return flash.WithSuccess(ctx, router.ViewContext{
		"system_message": "Successful user registration",
	}).Redirect(redirect, fiber.StatusSeeOther)
}

func (a *AuthController) PasswordResetForm(ctx router.Context) error {

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
		a.Logger.Error("verification error", err)
		errors["verification"] = err.Error()
		return ctx.Render(a.Views.PasswordReset, router.ViewContext{
			"errors": errors,
			"reset": map[string]string{
				stageKey:   ChangingPassword,
				sessionKey: sessionID,
				emailKey:   "",
			},
		})
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

	return ctx.Render(a.Views.PasswordReset, router.ViewContext{
		"errors": errors,
		"reset": map[string]string{
			sessionKey: sessionID,
			stageKey:   currentStage,
		},
	})
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

	sessionID := ctx.Param("uuid")

	errors := map[string]string{}
	payload := new(PasswordResetVerifyPayload)

	if err := ctx.Bind(payload); err != nil {
		errors["form"] = "Failed to parse form"
		a.Logger.Error("register user parse payload: ", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error parsing body",
		}).Status(fiber.StatusBadRequest).Render(a.Views.PasswordReset, router.ViewContext{
			"errors": errors,
			"record": payload,
		})
	}

	if err := payload.Validate(); err != nil {
		a.Logger.Error("register user validate payload", "error", err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Message,
			"system_message": "Error validating payload",
		}).Render(a.Views.PasswordReset, router.ViewContext{
			"record":     payload,
			"validation": err.ValidationMap(),
		})
	}

	input := FinalizePasswordResetMesasge{
		Session:  sessionID,
		Password: payload.Password,
	}

	finalizePwdReset := FinalizePasswordResetHandler{repo: a.Repo}

	if err := finalizePwdReset.Execute(ctx.Context(), input); err != nil {
		errors["validation"] = err.Error()
		return ctx.Render(a.Views.PasswordReset, router.ViewContext{
			"errors": errors,
			"reset": router.ViewContext{
				stageKey:   ChangingPassword,
				sessionKey: sessionID,
				emailKey:   "",
			},
		})
	}

	return ctx.Render(a.Views.PasswordReset, router.ViewContext{
		"errors": errors,
		"reset": router.ViewContext{
			stageKey:   ChangeFinalized,
			sessionKey: sessionID,
		},
	})
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
	return c.Render("errors/500", router.ViewContext{
		"message": err.Error(),
	})
}
