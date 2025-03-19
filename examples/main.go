package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth-examples/config"
	repo "github.com/goliatone/go-auth/repository"
	gconfig "github.com/goliatone/go-config/config"
	"github.com/goliatone/go-persistence-bun"
	"github.com/goliatone/go-print"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-router/flash"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

type App struct {
	config *gconfig.Container[*config.BaseConfig]
	bunDB  *bun.DB
	auth   auth.Authenticator
	auther auth.HTTPAuthenticator
	repo   auth.RepositoryManager
	srv    router.Server[*fiber.App]
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

	ctx := context.Background()

	cfg, err := gconfig.New(&config.BaseConfig{})
	if err != nil {
		panic(err)
	}

	if err := cfg.Load(ctx); err != nil {
		panic(err)
	}

	fmt.Println("============")
	fmt.Println(print.MaybePrettyJSON(cfg.Raw()))
	fmt.Println("============")

	app := &App{
		config: cfg,
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
}

func WithHTTPServer(ctx context.Context, app *App) error {
	srv := router.NewFiberAdapter(func(a *fiber.App) *fiber.App {
		engine, err := router.InitializeViewEngine(app.config.Raw().GetViews())
		if err != nil {
			panic(err)
		}

		return router.DefaultFiberOptions(fiber.New(fiber.Config{
			UnescapePath:      true,
			EnablePrintRoutes: true,
			StrictRouting:     false,
			PassLocalsToViews: true,
			Views:             engine,
		}))
	})

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
			"message": "This is your Home Page",
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

	client.SetLogger(log.Printf)
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
	athenticator := auth.NewAuthenticator(userProvider, cfg)

	app.SetAuthenticator(athenticator)

	httpAuth, err := auth.NewHTTPAuthenticator(athenticator, cfg)
	if err != nil {
		return err
	}

	app.SetHTTPAuth(httpAuth)

	auth.RegisterAuthRoutes(app.srv.Router().Group("/"),
		func(ac *auth.AuthController) *auth.AuthController {
			ac.Debug = true
			ac.Auther = httpAuth
			ac.Repo = repo
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
	ID             uuid.UUID  `json:"id"`
	FirstName      string     `json:"first_name"`
	LastName       string     `json:"last_name"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	Phone          string     `json:"phone_number"`
	EmailValidated bool       `json:"is_email_verified"`
	DeletedAt      *time.Time `json:"deleted_at"`
	ResetedAt      *time.Time `json:"reseted_at"`
	CreatedAt      *time.Time `json:"created_at"`
	UpdatedAt      *time.Time `json:"updated_at"`
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
		cookie := c.Cookies(contextKey)
		session, err := app.auth.SessionFromToken(cookie)
		if err != nil {
			return c.Render("errors/500", fiber.Map{
				"message": err.Error(),
			})
		}

		user, err := app.repo.Users().GetByID(c.Context(), session.GetUserID())
		if err != nil {
			return c.Render("errors/500", fiber.Map{
				"message": err.Error(),
			})
		}

		return c.Render("profile", fiber.Map{
			"errors": nil,
			"record": NewUserDTO(user),
		})
	}
}
