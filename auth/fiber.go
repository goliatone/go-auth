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
	Impersonate(c *fiber.Ctx, identifier string) error
	ProtectedRoute(cfg Config, errorHandler func(*fiber.Ctx, error)) func(ctx *fiber.Ctx) error
}

func GetSession(c *fiber.Ctx, key string) (Session, error) {
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

func RegisterAuthRoutes[T any](app router.Router[T]) {
	controller := NewAuthController()

	app.Get(controller.Routes.Login, controller.LoginShow)
	app.Post(controller.Routes.Login, controller.LoginPost)
	// app.Post(controller.Routes.Login, limitReq, controller.AuthLoginPost)

	app.Get(controller.Routes.Logout, controller.LogOut)

	app.Get(controller.Routes.Register, controller.RegistrationShow)
	app.Post(controller.Routes.Register, controller.RegistrationCreate)

	app.Get(controller.Routes.PasswordReset, controller.PasswordResetGet)
	app.Post(controller.Routes.PasswordReset, controller.PasswordResetPost)

	app.Get(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset), controller.PasswordResetForm)
	app.Post(fmt.Sprintf("%s/:uuid", controller.Routes.PasswordReset), controller.PasswordResetExecute)
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

type Logger interface {
	// Debug(format string, args ...any)
	// Info(format string, args ...any)
	Error(format string, args ...any)
}

type AuthController struct {
	Debug  bool
	Logger Logger
	Repo   RepositoryManager
	Routes *AuthControllerRoutes
	Views  *AuthControllerViews
}

func NewAuthController() *AuthController {
	return &AuthController{
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
}

func (a *AuthController) LoginShow(ctx router.Context) error {

	return ctx.Render(a.Routes.Login, router.ViewContext{
		"errors": nil,
		"record": nil,
	})
}
func (a *AuthController) LoginPost(ctx router.Context) error {

	return ctx.Render(a.Routes.Login, router.ViewContext{
		"errors": nil,
		"record": nil,
	})
}
func (a *AuthController) LogOut(ctx router.Context) error {

	return ctx.Render(a.Routes.Login, router.ViewContext{
		"errors": nil,
		"record": nil,
	})
}

func (a *AuthController) RegistrationShow(ctx router.Context) error {

	errors := map[string]string{}

	return ctx.Render(a.Views.Register, router.ViewContext{
		"errors": errors,
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

	errors := map[string]any{}
	payload := new(RegistrationCreatePayload)

	if err := ctx.Bind(payload); err != nil {
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

	ph := RegisterUserHandler{repo: a.Repo}

	if err := ph.Execute(ctx.Context(), req); err != nil {
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

	errors := map[string]any{}
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

	ph := InitializePasswordResetHandler{
		repo: a.Repo,
	}

	if err := ph.Execute(ctx.Context(), req); err != nil {
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

	ph := AccountVerificationHandler{repo: a.Repo}

	if err := ph.Execute(ctx.Context(), input); err != nil {
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

	ph := FinalizePasswordResetHandler{repo: a.Repo}

	if err := ph.Execute(ctx.Context(), input); err != nil {
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
	return func(value interface{}) error {
		s, _ := value.(string)
		if s != str {
			return errors.New("values must match")
		}
		return nil
	}
}
