package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gofiber/fiber/v2"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth-examples/config"
	repo "github.com/goliatone/go-auth/repository"
	cfs "github.com/goliatone/go-composite-fs"
	gconfig "github.com/goliatone/go-config/config"
	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-logger/glog"
	"github.com/goliatone/go-persistence-bun"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-router/flash"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// go embed ./public
var assetsFS embed.FS

type App struct {
	config *gconfig.Container[*config.BaseConfig]
	bunDB  *bun.DB
	auth   auth.Authenticator
	auther auth.HTTPAuthenticator
	repo   auth.RepositoryManager
	srv    router.Server[*fiber.App]
	logger *glog.BaseLogger
}

func (a *App) Config() *config.BaseConfig {
	return a.config.Raw()
}

func (a *App) SetRepository(repo auth.RepositoryManager) {
	a.repo = repo
}

func (a *App) SetDB(db *bun.DB) {
	a.bunDB = db
}

func (a *App) SetLogger(lgr *glog.BaseLogger) *App {
	a.logger = lgr
	return a
}

func (a *App) GetLogger(name string) glog.Logger {
	return a.logger.GetLogger(name)
}

func (a *App) SetHTTPServer(srv router.Server[*fiber.App]) {
	a.srv = srv
}

func (a *App) SetAuthenticator(auth auth.Authenticator) {
	a.auth = auth
}

func (a *App) SetHTTPAuth(auther auth.HTTPAuthenticator) {
	a.auther = auther
}

func main() {

	lgr := glog.NewLogger(
		glog.WithLoggerTypePretty(),
		glog.WithLevel(glog.Trace),
		glog.WithName("app"),
		glog.WithAddSource(false),
		glog.WithRichErrorHandler(errors.ToSlogAttributes),
	)

	cfg := gconfig.New(&config.BaseConfig{}).
		WithLogger(lgr.GetLogger("config"))

	ctx := context.Background()
	if err := cfg.Load(ctx); err != nil {
		panic(err)
	}

	fmt.Println("============")
	fmt.Println(print.MaybeHighlightJSON(cfg.Raw()))
	fmt.Println("============")

	app := &App{
		config: cfg,
		logger: lgr,
	}

	if err := WithPersistence(ctx, app); err != nil {
		panic(err)
	}

	if err := WithHTTPServer(ctx, app); err != nil {
		panic(err)
	}

	if err := WithHTTPAuth(ctx, app); err != nil {
		panic(err)
	}

	ProtectedRoutes(app)

	app.srv.Serve(":8978")

	WaitExitSignal()

}

func ProtectedRoutes(app *App) {

	p := app.srv.Router()

	cfg := app.Config().GetAuth()

	protected := app.auther.ProtectedRoute(
		cfg,
		app.auther.MakeClientRouteAuthErrorHandler(false),
	)

	p.Get("/me", ProfileShow(app), protected)
	p.Post("/me", ProfileUpdate(app), protected)
}

func WithHTTPServer(ctx context.Context, app *App) error {
	vcfg := app.Config().GetViews()

	vcfg.SetAssetsFS(
		cfs.NewCompositeFS(
			assetsFS,
			os.DirFS(vcfg.GetAssetsDir()),
		),
	)

	comp := cfs.NewCompositeFS(
		os.DirFS(vcfg.GetDirFS()),
	)
	vcfg.SetTemplatesFS([]fs.FS{comp})

	engine, err := router.InitializeViewEngine(vcfg, app.GetLogger("views"))
	if err != nil {
		return err
	}

	srv := router.NewFiberAdapter(func(a *fiber.App) *fiber.App {
		return router.DefaultFiberOptions(fiber.New(fiber.Config{
			UnescapePath:      true,
			EnablePrintRoutes: true,
			StrictRouting:     false,
			PassLocalsToViews: true,
			Views:             engine,
		}))
	})

	srv.Router().WithLogger(app.GetLogger("router"))

	srv.Router().Use(flash.ToMiddleware(flash.DefaultFlash, "flash"))

	srv.Router().Get("/test", func(ctx router.Context) error {
		return ctx.Render("test", router.ViewContext{
			"title":   "View Renderer",
			"message": "This is a message renderer",
		})
	})

	srv.Router().Get("/", func(ctx router.Context) error {
		return ctx.Render("test", router.ViewContext{
			"title":   "Home Renderer",
			"message": `<p>This is your Home Page</p><a href="/me">Profile</a>`,
		})
	})

	srv.Router().Static("/", "./public")

	app.SetHTTPServer(srv)

	return nil
}

func WithPersistence(ctx context.Context, app *App) error {
	db, err := sql.Open(sqliteshim.ShimName, app.config.Raw().GetPersistence().GetDSN())
	if err != nil {
		log.Fatal(err)
		return err
	}

	persistence.RegisterModel((*auth.User)(nil))
	persistence.RegisterModel((*auth.PasswordReset)(nil))

	// cfg := app.Config().GetPersistence()
	cfg := app.config.Raw().GetPersistence()
	dialect := sqlitedialect.New()
	client, err := persistence.New(cfg, db, dialect)
	if err != nil {
		log.Fatal(err)
		return err
	}

	client.SetLogger(app.GetLogger("persistence"))
	client.RegisterSQLMigrations(auth.GetMigrationsFS())

	if err := client.Migrate(context.Background()); err != nil {
		return err
	}

	if report := client.Report(); report != nil && !report.IsZero() {
		fmt.Printf("report: %s\n", report.String())
	}

	app.SetDB(client.DB())
	app.SetRepository(repo.NewRepositoryManager(client.DB()))

	return nil
}

func WithHTTPAuth(ctx context.Context, app *App) error {
	cfg := app.Config().GetAuth()

	repo := auth.NewRepositoryManager(app.bunDB)

	if err := repo.Validate(); err != nil {
		return err
	}

	userProvider := auth.NewUserProvider(repo.Users())
	userProvider.WithLogger(app.GetLogger("auth:prv"))

	athenticator := auth.NewAuthenticator(userProvider, cfg)
	athenticator.WithLogger(app.GetLogger("auth:authz"))

	app.SetAuthenticator(athenticator)

	httpAuth, err := auth.NewHTTPAuthenticator(athenticator, cfg)
	if err != nil {
		return err
	}

	httpAuth.WithLogger(app.GetLogger("auth:http"))

	app.SetHTTPAuth(httpAuth)

	auth.RegisterAuthRoutes(app.srv.Router().Group("/"),
		func(ac *auth.AuthController) *auth.AuthController {
			ac.Debug = true
			ac.Auther = httpAuth
			ac.Repo = repo
			ac.WithLogger(app.GetLogger("auth:ctrl"))
			return ac
		})

	return nil
}

func WaitExitSignal() os.Signal {
	ch := make(chan os.Signal, 3)
	signal.Notify(ch,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
	)
	return <-ch
}

/////

type UserRecord struct {
	ID             uuid.UUID  `form:"id" json:"id"`
	FirstName      string     `form:"first_name" json:"first_name"`
	LastName       string     `form:"last_name" json:"last_name"`
	Username       string     `form:"username" json:"username"`
	Email          string     `form:"email" json:"email"`
	Phone          string     `form:"phone_number" json:"phone_number"`
	ProfilePicture string     `form:"profile_picture" json:"profile_picture"`
	EmailValidated bool       `form:"is_email_verified" json:"is_email_verified"`
	DeletedAt      *time.Time `form:"deleted_at" json:"deleted_at"`
	ResetedAt      *time.Time `form:"reseted_at" json:"reseted_at"`
	CreatedAt      *time.Time `form:"created_at" json:"created_at"`
	UpdatedAt      *time.Time `form:"updated_at" json:"updated_at"`
}

// Validate will run validation rules
func (r UserRecord) Validate() *errors.Error {
	return errors.ValidateWithOzzo(func() error {
		return validation.ValidateStruct(&r,
			validation.Field(
				&r.ID,
				validation.Required,
				is.UUID,
			),
		)
	}, "Invalid login request payload")

}

func NewUserDTO(user *auth.User) UserRecord {
	return UserRecord{
		ID:             user.ID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Username:       user.Username,
		Email:          user.Email,
		Phone:          user.Phone,
		EmailValidated: user.EmailValidated,
	}
}

// ProfileShow will render the user's profile page
func ProfileShow(app *App) func(c router.Context) error {

	contextKey := app.Config().GetAuth().GetContextKey()

	return func(c router.Context) error {
		session, err := auth.GetRouterSession(c, contextKey)
		if err != nil {
			app.GetLogger("profile").Error("Session Auth error", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		}

		user, err := app.repo.Users().GetByID(c.Context(), session.GetUserID())
		if err != nil {
			app.GetLogger("profile").Error("User GetByID error", "details", err)
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		return c.Render("profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
		})
	}
}

// ProfileUpdate will render the user's profile page
func ProfileUpdate(app *App) func(c router.Context) error {
	contextKey := app.Config().GetAuth().GetContextKey()
	return func(c router.Context) error {
		session, err := auth.GetRouterSession(c, contextKey)
		if err != nil {
			app.GetLogger("profile").Error("Session Auth error", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		}

		payload := new(UserRecord)

		if err := c.Bind(payload); err != nil {
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		if err := payload.Validate(); err != nil {
			return flash.WithError(c, router.ViewContext{
				"error_message":  err.Message,
				"system_message": "Error validating payload",
			}).Render("profile", router.ViewContext{
				"record":     payload,
				"validation": err.ValidationMap(),
			})
		}

		uid, err := session.GetUserUUID()
		if err != nil {
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		record := &auth.User{
			ID:             uid,
			FirstName:      payload.FirstName,
			LastName:       payload.LastName,
			Username:       payload.Username,
			ProfilePicture: payload.ProfilePicture,
		}

		user, err := app.repo.Users().Update(c.Context(), record)
		if err != nil {
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		return c.Render("profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
		})
	}
}
