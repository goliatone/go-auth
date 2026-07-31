package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/gofiber/fiber/v2"
	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-auth-examples/config"
	csfmw "github.com/goliatone/go-auth/middleware/csrf"
	"github.com/goliatone/go-auth/middleware/jwtware"
	repo "github.com/goliatone/go-auth/repository"
	cfs "github.com/goliatone/go-composite-fs"
	gconfig "github.com/goliatone/go-config/config"
	"github.com/goliatone/go-errors"
	"github.com/goliatone/go-logger/glog"
	"github.com/goliatone/go-persistence-bun"
	"github.com/goliatone/go-router"
	"github.com/goliatone/go-router/flash"
	mflash "github.com/goliatone/go-router/middleware/flash"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// We embed assets and templates together so the view engine can auto-root them
// once; disk FS is layered on top only to allow local overrides during dev.
//
//go:embed public views
var embeddedFS embed.FS

//go:embed data/fixtures/*.yml
var fixturesFS embed.FS

type App struct {
	config *gconfig.Container[*config.BaseConfig]
	bunDB  *bun.DB
	auth   auth.Authenticator
	auther auth.HTTPAuthenticator
	repo   auth.RepositoryManager
	srv    router.Server[*fiber.App]
	logger *glog.BaseLogger
}

// UsersGuard models the go-users guard adapter, enforcing actor scope before allowing CRUD actions.
type UsersGuard interface {
	Authorize(ctx context.Context, actor *auth.ActorContext, action string) error
}

// ExampleUsersScopeGuard demonstrates how go-users would consume the actor payload injected by the middleware.
type ExampleUsersScopeGuard struct {
	logger glog.Logger
}

func (g ExampleUsersScopeGuard) Authorize(ctx context.Context, actor *auth.ActorContext, action string) error {
	if actor == nil {
		return errors.New("missing actor context", errors.CategoryAuth).
			WithCode(errors.CodeUnauthorized)
	}

	if actor.TenantID == "" {
		return errors.New("tenant scope required for admin guard", errors.CategoryAuth).
			WithCode(errors.CodeForbidden)
	}

	if actor.IsImpersonated && g.logger != nil {
		g.logger.Warn("impersonated request", "actor_id", actor.ActorID, "impersonator_id", actor.ImpersonatorID)
	}

	// Owners/admins can access every action; otherwise fall back to resource roles.
	if actor.Role == "owner" || actor.Role == "admin" {
		return nil
	}

	if role, ok := actor.ResourceRoles["admin:users"]; ok && role != "" {
		return nil
	}

	return errors.New("insufficient permissions for "+action, errors.CategoryAuth).
		WithCode(errors.CodeForbidden).
		WithMetadata(map[string]any{
			"actor_id": actor.ActorID,
			"tenant":   actor.TenantID,
			"action":   action,
		})
}

// GuardMiddleware is the transport glue go-users/go-crud controllers use to run the guard before handlers.
func GuardMiddleware(guard UsersGuard, action string) router.MiddlewareFunc {
	return func(next router.HandlerFunc) router.HandlerFunc {
		return func(ctx router.Context) error {
			actor, ok := auth.ActorFromRouterContext(ctx)
			if !ok {
				return ctx.Status(http.StatusUnauthorized).SendString("missing actor context")
			}

			if err := guard.Authorize(ctx.Context(), actor, action); err != nil {
				return ctx.Status(http.StatusForbidden).SendString(err.Error())
			}

			return next(ctx)
		}
	}
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
		exitStartup(startupFailure("config.load", startupCodeConfigLoad, err))
	}

	app := &App{
		config: cfg,
		logger: lgr,
	}

	if err := WithPersistence(ctx, app); err != nil {
		exitStartup(err)
	}

	if err := WithHTTPServer(ctx, app); err != nil {
		exitStartup(startupFailure("http.server.construct", startupCodeHTTPServerConstruct, err))
	}

	if err := WithHTTPAuth(ctx, app); err != nil {
		exitStartup(startupFailure("http.auth.construct", startupCodeHTTPAuthConstruct, err))
	}

	ProtectedRoutes(app)

	if err := app.srv.Serve(":8572"); err != nil {
		exitStartup(startupFailure("http.server.serve", startupCodeHTTPServerServe, err))
	}

	WaitExitSignal()

}

func ProtectedRoutes(app *App) {

	p := app.srv.Router()

	cfg := app.Config().GetAuth()

	protected := app.auther.ProtectedRoute(cfg, app.auther.MakeClientRouteAuthErrorHandler(false))
	usersGuard := GuardMiddleware(
		ExampleUsersScopeGuard{logger: app.GetLogger("guard")},
		"users:list",
	)

	p.Get("/me", ProfileShow(app), protected)
	p.Post("/me", ProfileUpdate(app), protected)
	p.Get("/protected-page", ProtectedPage(app), protected)
	p.Get("/admin/users", AdminUsersIndex(app), protected, usersGuard)
}

func renderWithGlobals(ctx router.Context, name string, data router.ViewContext) error {
	return ctx.Render(name, auth.MergeTemplateData(ctx, data))
}

func cleanFSPath(value string) string {
	value = filepath.ToSlash(filepath.Clean(strings.TrimSpace(value)))
	value = strings.TrimPrefix(value, "./")
	value = strings.Trim(value, "/")
	if value == "" {
		return "."
	}
	return value
}

func subOrRoot(fsys fs.FS, dir string) fs.FS {
	dir = cleanFSPath(dir)
	if dir == "." {
		return fsys
	}
	if _, err := fs.Stat(fsys, dir); err == nil {
		if sub, subErr := fs.Sub(fsys, dir); subErr == nil {
			return sub
		}
	}
	return fsys
}

func resolveExampleDirectory(dir string) string {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = "."
	}
	return resolveExampleDirectoryFrom(workingDir, dir)
}

func resolveExampleDirectoryFrom(workingDir, dir string) string {
	dir = filepath.FromSlash(cleanFSPath(dir))
	candidates := []string{
		filepath.Join(workingDir, dir),
		filepath.Join(workingDir, "examples", dir),
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate
		}
	}
	return candidates[0]
}

func normalizeAssetURLPrefix(value string) (string, error) {
	prefix := router.NormalizePath(value)
	if prefix == "" || prefix == ".." || strings.HasPrefix(prefix, "../") {
		return "", errors.New(
			startupMessages[startupCodeAssetPrefixInvalid],
			errors.CategoryValidation,
		).
			WithTextCode(startupCodeAssetPrefixInvalid).
			WithMetadata(map[string]any{"field": "views.url_prefix"})
	}
	return "/" + prefix, nil
}

func assetURL(prefix, name string) string {
	return path.Join(prefix, strings.TrimLeft(filepath.ToSlash(name), "/"))
}

func newAssetFileSystem(embeddedSource fs.FS, assetDir, diskDir string) fs.FS {
	embeddedAssets := subOrRoot(embeddedSource, assetDir)
	return cfs.NewOverlayFS(os.DirFS(diskDir), embeddedAssets)
}

func WithHTTPServer(ctx context.Context, app *App) error {
	vcfg := app.Config().GetViews()
	viewLogger := app.GetLogger("views")

	assetDir := cleanFSPath(vcfg.GetAssetsDir())
	assetPrefix, err := normalizeAssetURLPrefix(vcfg.GetURLPrefix())
	if err != nil {
		return err
	}

	// Disk assets override embedded defaults. NewOverlayFS merges directory
	// entries so a development override can replace one file without hiding
	// embedded siblings from the view engine's glob helpers.
	assetDiskPath := resolveExampleDirectory(assetDir)
	assetFS := newAssetFileSystem(fs.FS(embeddedFS), assetDir, assetDiskPath)
	vcfg.AssetsDir = "."
	vcfg.SetAssetsFS(assetFS)

	// Templates: let the view initializer perform exactly one sub by providing an
	// unscoped composite and setting DirFS to the clean template root.
	templateDir := cleanFSPath(vcfg.GetDirFS())
	if templateDir == "." {
		templateDir = "views"
	}

	// Scope embedded templates to templateDir; fail fast if missing to avoid silent prefix drift.
	embeddedTemplates, err := fs.Sub(embeddedFS, templateDir)
	if err != nil {
		return fmt.Errorf("unable to scope embedded templates to %q: %w", templateDir, err)
	}

	// Use the same repository-root/examples-directory resolution for templates
	// and assets so both documented invocation locations behave identically.
	diskPath := resolveExampleDirectory(templateDir)
	diskTemplates := os.DirFS(diskPath)

	// Disk overrides embedded, so it comes first.
	var templatesFS fs.FS = cfs.NewOverlayFS(diskTemplates, embeddedTemplates)
	// We already scoped the FSs, so expose them at root to the view engine.
	vcfg.DirFS = "."
	vcfg.SetTemplatesFS([]fs.FS{templatesFS})

	// Keep every generated asset URL on the same configured namespace.
	templateFunctions := auth.TemplateHelpers()
	templateFunctions["asset_url"] = func(name string) string {
		return assetURL(assetPrefix, name)
	}
	vcfg.SetTemplateFunctions(templateFunctions)

	vcfg.Debug = false
	engine, err := router.InitializeViewEngine(vcfg, viewLogger)
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

	// key := sha256.Sum256([]byte(app.Config().GetAuth().GetSigningKey()))
	// srv.Router().Use(csrf.New(csrf.Config{
	// 	SecureKey: key[:],
	// }))

	// csrf.RegisterRoutes(srv.Router())

	srv.Router().Use(mflash.New(mflash.ConfigDefault))

	srv.Router().Get("/test", func(ctx router.Context) error {
		return renderWithGlobals(ctx, "test", router.ViewContext{
			"title":   "View Renderer",
			"message": "This is a message renderer",
		})
	})

	srv.Router().Get("/", func(ctx router.Context) error {
		return renderWithGlobals(ctx, "home", router.ViewContext{
			"title": "Home Renderer",
		})
	})

	srv.Router().Static(assetPrefix, ".", router.Static{
		FS:   assetFS,
		Root: ".",
	})

	app.SetHTTPServer(srv)

	return nil
}

type userTrackerAdapter struct {
	users auth.Users
}

func (a userTrackerAdapter) GetByIdentifier(ctx context.Context, identifier string) (*auth.User, error) {
	return a.users.GetByIdentifier(ctx, identifier)
}

func (a userTrackerAdapter) TrackAttemptedLogin(ctx context.Context, user *auth.User) error {
	return a.users.TrackAttemptedLogin(ctx, user)
}

func (a userTrackerAdapter) ReserveLoginAttempt(ctx context.Context, userID uuid.UUID, policy auth.LoginAttemptPolicy) (auth.LoginAttemptReservation, error) {
	return a.users.(auth.AtomicLoginAttemptTracker).ReserveLoginAttempt(ctx, userID, policy)
}

func (a userTrackerAdapter) TrackSucccessfulLogin(ctx context.Context, user *auth.User) error {
	return a.users.TrackSucccessfulLogin(ctx, user)
}

func WithPersistence(ctx context.Context, app *App) error {
	db, err := sql.Open(sqliteshim.ShimName, app.config.Raw().GetPersistence().GetDSN())
	if err != nil {
		return startupFailure("persistence.open", startupCodePersistenceOpen, err)
	}
	ready := false
	defer func() {
		if !ready {
			_ = db.Close()
		}
	}()

	persistence.RegisterModel((*auth.User)(nil))
	persistence.RegisterModel((*auth.PasswordReset)(nil))

	// cfg := app.Config().GetPersistence()
	cfg := app.config.Raw().GetPersistence()
	dialect := sqlitedialect.New()
	client, err := persistence.New(cfg, db, dialect)
	if err != nil {
		return startupFailure("persistence.construct", startupCodePersistenceConstruct, err)
	}

	client.SetLogger(app.GetLogger("persistence"))
	migrationsFS, err := fs.Sub(auth.GetMigrationsFS(), "data/sql/migrations")
	if err != nil {
		return startupFailure("persistence.migrations.source", startupCodeMigrationSource, err)
	}
	client.RegisterDialectMigrations(
		migrationsFS,
		persistence.WithDialectSourceLabel("data/sql/migrations"),
		persistence.WithValidationTargets("postgres", "sqlite"),
	)
	if err := client.ValidateDialects(context.Background()); err != nil {
		return startupFailure("persistence.migrations.validate", startupCodeMigrationValidation, err)
	}

	if err := client.Migrate(ctx); err != nil {
		return startupFailure("persistence.migrations.apply", startupCodeMigrationApply, err)
	}

	client.RegisterFixtures(fixturesFS).AddOptions(persistence.WithTrucateTables())

	if err := client.Seed(ctx); err != nil {
		return startupFailure("persistence.fixtures.seed", startupCodeFixtureSeed, err)
	}

	if report := client.Report(); report != nil && !report.IsZero() {
		fmt.Printf("report: %s\n", report.String())
	}

	app.SetDB(client.DB())
	app.SetRepository(repo.NewRepositoryManager(client.DB()))
	ready = true

	return nil
}

// ExampleResourceRoleProvider demonstrates how to implement a custom ResourceRoleProvider
// This example shows a simple role provider that assigns resource-specific roles based on user roles.
// In a real application, you would typically fetch this data from a database or external service.
type ExampleResourceRoleProvider struct {
	repo   auth.RepositoryManager
	logger glog.Logger
}

// FindResourceRoles implements the ResourceRoleProvider interface
func (p *ExampleResourceRoleProvider) FindResourceRoles(ctx context.Context, identity auth.Identity) (map[string]string, error) {
	// In this example, we'll provide different resource access based on the user's global role
	userRole := identity.Role()
	resourceRoles := make(map[string]string)

	// Example resource roles based on user's global role
	switch userRole {
	case "admin":
		// Admin users get owner access to admin resources and member access to projects
		resourceRoles["admin:dashboard"] = "owner"
		resourceRoles["admin:settings"] = "owner"
		resourceRoles["admin:users"] = "owner"
		resourceRoles["project:default"] = "admin"

	case "moderator":
		// Moderators get admin access to some resources and member access to projects
		resourceRoles["admin:dashboard"] = "member"
		resourceRoles["project:default"] = "admin"

	case "user":
		// Regular users get member access to their assigned projects
		resourceRoles["project:default"] = "member"

	case "guest":
		// Guests only get read access to public resources
		resourceRoles["project:public"] = "guest"

	default:
		// Unknown roles get minimal access
		p.logger.Warn("Unknown user role, providing minimal access", "role", userRole, "user_id", identity.ID())
	}

	// In a real application, you might also query the database for user-specific permissions:
	//
	// userID := identity.ID()
	// permissions, err := p.repo.GetUserPermissions(ctx, userID)
	// if err != nil {
	//     return nil, fmt.Errorf("failed to fetch user permissions: %w", err)
	// }
	//
	// for resource, role := range permissions {
	//     resourceRoles[resource] = role
	// }

	p.logger.Debug("Generated resource roles for user",
		"user_id", identity.ID(),
		"user_role", userRole,
		"resource_count", len(resourceRoles))

	return resourceRoles, nil
}

func WithHTTPAuth(ctx context.Context, app *App) error {
	cfg := app.Config().GetAuth()

	repo := auth.NewRepositoryManager(app.bunDB)

	if err := repo.Validate(); err != nil {
		return err
	}

	userProvider := auth.NewUserProvider(userTrackerAdapter{users: repo.Users()})
	userProvider.WithLogger(app.GetLogger("auth:prv"))

	// Step 1: Create a standard authenticator (backward compatible)
	// This will use the default no-op resource role provider internally
	authenticator := auth.NewAuthenticator(userProvider, cfg)
	authenticator.WithLogger(app.GetLogger("auth:authz"))

	// Step 2: Optionally enhance the authenticator with resource-level permissions
	// This is completely opt-in and doesn't break existing functionality
	// Comment/uncomment the next block to see the difference

	// Enhanced mode: Add custom resource role provider for fine-grained permissions
	resourceRoleProvider := &ExampleResourceRoleProvider{
		repo:   repo,
		logger: app.GetLogger("auth:roles"),
	}
	authenticator.WithResourceRoleProvider(resourceRoleProvider)

	// The authenticator will now generate JWT tokens with resource-specific roles
	// which enable fine-grained permission checking in your application

	app.SetAuthenticator(authenticator)

	httpAuth, err := auth.NewHTTPAuthenticator(authenticator, cfg)
	if err != nil {
		return err
	}

	httpAuth.WithLogger(app.GetLogger("auth:http"))
	httpAuth.WithValidationListeners(func(ctx router.Context, claims jwtware.AuthClaims) error {
		authClaims, ok := claims.(auth.AuthClaims)
		if !ok {
			return nil
		}

		actor := auth.ActorContextFromClaims(authClaims)
		if actor != nil {
			app.GetLogger("auth:listener").Info("validated token",
				"actor_id", actor.ActorID,
				"tenant_id", actor.TenantID,
			)
		}
		return nil
	})

	app.SetHTTPAuth(httpAuth)

	err = auth.RegisterSecureAuthRoutes(
		app.srv.Router().Group("/"),
		auth.AuthRouteSecurityConfig{
			CSRF: csfmw.Config{
				SecureKey: auth.DeriveBrowserCSRFSecureKey(cfg),
				ErrorHandler: func(ctx router.Context, err error) error {
					return ctx.Status(http.StatusForbidden).SendString(err.Error())
				},
			},
		},
		func(ac *auth.AuthController) *auth.AuthController {
			ac.Debug = true
			ac.Auther = httpAuth
			ac.Repo = repo
			ac.WithLogger(app.GetLogger("auth:ctrl"))
			return ac
		},
	)
	if err != nil {
		return err
	}

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
// Note: current_user is automatically injected by JWT middleware
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
			return renderWithGlobals(c, "errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		// Simplified - current_user automatically available from JWT middleware!
		app.GetLogger("profile").Debug("Rendering profile with automatic current_user injection",
			"user_id", session.GetUserID())

		return renderWithGlobals(c, "profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
			// current_user automatically injected by JWT middleware
		})
	}
}

// ProtectedPage renders a placeholder for sandboxing feature experiments
func ProtectedPage(app *App) func(c router.Context) error {
	return func(c router.Context) error {
		actor, _ := auth.ActorFromRouterContext(c)
		return renderWithGlobals(c, "protected_page", router.ViewContext{
			"actor": actor,
		})
	}
}

// AdminUsersIndex demonstrates how go-users controllers can depend on the actor payload provided by the middleware.
func AdminUsersIndex(app *App) func(c router.Context) error {
	return func(c router.Context) error {
		actor, _ := auth.ActorFromRouterContext(c)
		message := fmt.Sprintf("tenant=%s actor=%s is authorized to list users", actor.TenantID, actor.ActorID)
		return c.Status(http.StatusOK).SendString(message)
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

		if bindErr := c.Bind(payload); bindErr != nil {
			return renderWithGlobals(c, "errors/500", router.ViewContext{
				"message": bindErr.Error(),
			})
		}

		if validationErr := payload.Validate(); validationErr != nil {
			return flash.WithError(c, auth.MergeTemplateData(c, router.ViewContext{
				"error_message":  validationErr.Message,
				"system_message": "Error validating payload",
			})).Render("profile", auth.MergeTemplateData(c, router.ViewContext{
				"record":     payload,
				"validation": validationErr.ValidationMap(),
			}))
		}

		uid, err := session.GetUserUUID()
		if err != nil {
			return renderWithGlobals(c, "errors/500", router.ViewContext{
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
			return renderWithGlobals(c, "errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		// Simplified - current_user automatically available from JWT middleware!
		return renderWithGlobals(c, "profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
			// current_user automatically injected by JWT middleware
		})
	}
}
