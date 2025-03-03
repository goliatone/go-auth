package auth

import (
	"errors"
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
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
		SetName("sign-in.get")

	app.
		Post(
			controller.Routes.Login,
			// limitReq,
			controller.LoginPost,
		).
		SetName("sign-in.post")

	app.Get(controller.Routes.Logout, controller.LogOut).SetName("sign-out.get")

	app.Get(controller.Routes.Register, controller.RegistrationShow).
		SetName("register.get")
	app.Post(controller.Routes.Register, controller.RegistrationCreate).
		SetName("register.post")

	app.Get(controller.Routes.PasswordReset, controller.PasswordResetGet).
		SetName("pwd-reset.get")
	app.Post(controller.Routes.PasswordReset, controller.PasswordResetPost).
		SetName("pwd-reset.post")

	app.Get(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset), controller.PasswordResetForm).
		SetName("pwd-reset-do.get")
	app.Post(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset), controller.PasswordResetExecute).
		SetName("pwd-reset-do.post")
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
	Debug        bool
	Logger       Logger
	Repo         RepositoryManager
	Routes       *AuthControllerRoutes
	Views        *AuthControllerViews
	Auther       HTTPAuthenticator
	ErrorHandler router.ErrorHandler
}

type AuthControllerOption func(*AuthController) *AuthController

func NewAuthController(opts ...AuthControllerOption) *AuthController {
	c := &AuthController{
		Logger:       defLogger{},
		ErrorHandler: defaultErrHandler,
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
func (r LoginRequest) Validate() error {
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
}

func (a *AuthController) LoginPost(ctx router.Context) error {
	payload := new(LoginRequest)
	errors := map[string]string{}
	fmt.Println("--- Login Post")

	if err := ctx.Bind(payload); err != nil {
		fmt.Println("--- Login Post: error bind" + err.Error())
		return a.ErrorHandler(ctx, err)
	}

	if err := payload.Validate(); err != nil {
		fmt.Println("--- Login Post: error valid" + err.Error())
		return ctx.Render(a.Views.Login, router.ViewContext{
			"record":     payload,
			"validation": err.Error(),
		})
	}

	if a.Debug {
		fmt.Println("======= AUTH LOGIN ======")
		fmt.Println(print.MaybePrettyJSON(payload))
		fmt.Println("=========================")
	}

	if err := a.Auther.Login(ctx, payload); err != nil {
		errors["authentication"] = "Authentication Error"
		return ctx.Render(a.Views.Login, router.ViewContext{
			"errors":  errors,
			"payload": payload,
		})
	}

	redirect := a.Auther.GetRedirect(ctx, "/")

	fmt.Println("redirecting to: " + redirect)

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
func (r RegistrationCreatePayload) Validate() error {

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
		errors := FormatValidationErrorToMap(err)
		a.Logger.Error("register user validate payload: ", "error", err)

		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error validating payload",
		}).Render(a.Views.Register, router.ViewContext{
			"record":     payload,
			"validation": errors,
		})
	}

	req := RegisterUserMessage{
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Email:     payload.Email,
		Phone:     payload.Phone,
		Password:  payload.Password,
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

	return flash.WithSuccess(ctx, router.ViewContext{
		"system_message": "Successful user registration",
	}).Redirect("/", fiber.StatusSeeOther)
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
func (r PasswordResetRequestPayload) Validate() error {
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
		errors := FormatValidationErrorToMap(err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error validating payload",
		}).Render(a.Views.PasswordReset, router.ViewContext{
			"record":     payload,
			"validation": errors,
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
		fmt.Println("================")
		fmt.Println(print.MaybePrettyJSON(res))
		fmt.Println("================")
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
		fmt.Println("verification error " + err.Error())
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

	fmt.Println("======= Password Reset ======")
	fmt.Println(print.MaybePrettyJSON(resp))
	fmt.Println("=============================")

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
func (r PasswordResetVerifyPayload) Validate() error {

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
		a.Logger.Error("register user validate payload: ", "error", err)
		errors = FormatValidationErrorToMap(err)
		return flash.WithError(ctx, router.ViewContext{
			"error_message":  err.Error(),
			"system_message": "Error validating payload",
		}).Render(a.Views.PasswordReset, router.ViewContext{
			"record":     payload,
			"validation": errors,
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
			return errors.New("values must match")
		}
		return nil
	}
}

func defaultErrHandler(c router.Context, err error) error {
	return c.Render("errors/500", router.ViewContext{
		"message": err.Error(),
	})
}
