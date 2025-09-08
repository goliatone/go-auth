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
	"github.com/goliatone/go-auth/middleware/jwtware"
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
	WebSocketRoutes(app)

	app.srv.Serve(":8978")

	WaitExitSignal()

}

func ProtectedRoutes(app *App) {

	p := app.srv.Router()

	cfg := app.Config().GetAuth()

	// Create enhanced JWT middleware with template support
	protected := CreateTemplateAwareJWTMiddleware(app, cfg)

	p.Get("/me", ProfileShow(app), protected)
	p.Post("/me", ProfileUpdate(app), protected)
	p.Get("/websocket-demo", WebSocketDemoShow(app), protected)
}

func WebSocketRoutes(app *App) {
	routerInstance := app.srv.Router()

	// Register Fiber WebSocket factory for go-router compatibility
	router.RegisterFiberWebSocketFactory(nil)

	// Create WebSocket token validator using our authenticator
	tokenValidator := &WebSocketTokenValidator{auth: app.auth}

	// For now, skip query-based authentication and handle auth via first message
	// We'll authenticate when the client sends their first message with the token

	// Note: Middleware not needed since authentication is handled in message handlers

	// Create WebSocket hub for managing connections
	hub := router.NewWSHub()

	// Handle new connections (authentication will happen via first message)
	hub.OnConnect(func(ctx context.Context, client router.WSClient, _ any) error {
		app.GetLogger("websocket").Info("🔗 New WebSocket connection established", "client_id", client.ID())
		app.GetLogger("websocket").Info("query request", "token", client.Query("token"))

		// Send a message requesting authentication
		authReqMsg := map[string]any{
			"type":    "auth_required",
			"message": "Please send your authentication token to continue",
		}

		app.GetLogger("websocket").Info("📤 Sending auth_required message", "client_id", client.ID(), "message", authReqMsg)

		err := client.SendJSON(authReqMsg)
		if err != nil {
			app.GetLogger("websocket").Error("❌ Failed to send auth_required", "client_id", client.ID(), "error", err)
			return err
		}

		app.GetLogger("websocket").Info("✅ Auth_required message sent successfully", "client_id", client.ID())

		token := client.Query("token", "")
		if token == "" {
			app.GetLogger("websocket").Error("❌ Token missing or invalid", "client_id", client.ID(), "token_empty", token == "")
			return client.SendJSON(map[string]any{
				"type":    "auth_error",
				"message": "No token provided",
			})
		}

		app.GetLogger("websocket").Info("✅ Token extracted", "client_id", client.ID(), "token_length", len(token))

		// Validate the token using our token validator
		claims, err := tokenValidator.Validate(token)
		if err != nil {
			app.GetLogger("websocket").Error("❌ Token validation failed", "error", err, "client_id", client.ID(), "token_length", len(token))
			return client.SendJSON(map[string]any{
				"type":    "auth_error",
				"message": "Invalid token",
			})
		}

		app.GetLogger("websocket").Info("✅ Token validated successfully", "client_id", client.ID(), "user_id", claims.UserID(), "role", claims.Role())

		// Store user information in client state
		client.Set("user_id", claims.UserID())
		client.Set("role", claims.Role())
		client.Set("authenticated", true)

		// Join user to appropriate rooms
		client.Join("users")
		if claims.HasRole("admin") {
			client.Join("admins")
		}

		app.GetLogger("websocket").Info("✅ User authenticated via WebSocket",
			"client_id", client.ID(),
			"user_id", claims.UserID(),
			"role", claims.Role())

		// Send success response
		successMsg := map[string]any{
			"type":    "auth_success",
			"message": fmt.Sprintf("Welcome %s! You are connected as %s", claims.UserID(), claims.Role()),
			"user_id": claims.UserID(),
			"role":    claims.Role(),
		}

		app.GetLogger("websocket").Info("📤 Sending auth success message", "client_id", client.ID(), "message", successMsg)

		err = client.SendJSON(successMsg)
		if err != nil {
			app.GetLogger("websocket").Error("❌ Failed to send auth success message", "client_id", client.ID(), "error", err)
			return err
		}

		app.GetLogger("websocket").Info("✅ Auth success message sent", "client_id", client.ID())

		return nil
	})

	// Handle disconnections
	hub.OnDisconnect(func(ctx context.Context, client router.WSClient, _ any) error {
		userID := client.GetString("user_id")
		app.GetLogger("websocket").Info("User disconnected", "user_id", userID)

		// Notify other users in the same rooms
		for _, room := range client.Rooms() {
			client.Room(room).Except(client).Emit("user_disconnected", map[string]string{
				"user_id": userID,
			})
		}

		return nil
	})

	// Handle chat messages with permission checking
	hub.On("chat_message", func(ctx context.Context, client router.WSClient, data any) error {
		// Check if user is authenticated
		if !client.GetBool("authenticated") {
			return client.SendJSON(map[string]any{
				"type":    "error",
				"message": "Authentication required",
			})
		}

		userID := client.GetString("user_id")
		role := client.GetString("role")

		messageData := data.(map[string]any)

		// Broadcast message to all users
		response := map[string]any{
			"type":      "new_message",
			"user_id":   userID,
			"role":      role,
			"message":   messageData["text"],
			"timestamp": time.Now().Format(time.RFC3339),
		}

		client.Room("users").Emit("message", response)
		app.GetLogger("websocket").Debug("Chat message broadcasted", "user_id", userID)
		return nil
	})

	// Handle admin commands (admin-only)
	hub.On("admin_command", func(ctx context.Context, client router.WSClient, data any) error {
		// Check if user is authenticated
		if !client.GetBool("authenticated") {
			return client.SendJSON(map[string]any{
				"type":    "error",
				"message": "Authentication required",
			})
		}

		userID := client.GetString("user_id")
		role := client.GetString("role")

		// Check admin permissions
		if role != "admin" {
			return client.SendJSON(map[string]any{
				"type":    "error",
				"message": "Admin privileges required",
			})
		}

		commandData := data.(map[string]any)
		command := commandData["command"].(string)

		app.GetLogger("websocket").Info("Admin command executed", "user_id", userID, "command", command)

		// Broadcast admin notification
		client.Room("users").Emit("admin_announcement", map[string]any{
			"type":      "admin_announcement",
			"message":   fmt.Sprintf("Admin executed: %s", command),
			"admin_id":  userID,
			"timestamp": time.Now().Format(time.RFC3339),
		})

		return nil
	})

	// Apply WebSocket upgrade middleware and register route
	wsUpgradeMiddleware := router.WebSocketUpgrade(router.WebSocketConfig{})
	wrappedHandler := wsUpgradeMiddleware(hub.Handler())
	routerInstance.Get("/ws", wrappedHandler)
	app.GetLogger("websocket").Info("WebSocket server configured with authentication", "endpoint", "/ws")
}

// WebSocketDemoShow renders the WebSocket demo page
func WebSocketDemoShow(app *App) func(c router.Context) error {
	contextKey := app.Config().GetAuth().GetContextKey()

	return func(c router.Context) error {
		session, err := auth.GetRouterSession(c, contextKey)
		if err != nil {
			app.GetLogger("websocket").Error("Session Auth error", "error", err)
			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		}

		user, err := app.repo.Users().GetByID(c.Context(), session.GetUserID())
		if err != nil {
			app.GetLogger("websocket").Error("User GetByID error", "details", err)
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		// Generate a fresh JWT token for WebSocket connection using impersonation
		// This allows us to generate a token without password verification since we already have a valid session
		token, err := app.auth.Impersonate(c.Context(), session.GetUserID())
		if err != nil {
			app.GetLogger("websocket").Error("Failed to impersonate user for WebSocket token", "error", err)
			return c.Render("errors/500", router.ViewContext{
				"message": "Failed to generate WebSocket token",
			})
		}

		return c.Render("websocket_demo", router.ViewContext{
			"user":  NewUserDTO(user),
			"token": token,
			"wsUrl": "ws://localhost:8978/ws",
		})
	}
}

// CreateTemplateAwareJWTMiddleware creates JWT middleware with automatic current_user injection
func CreateTemplateAwareJWTMiddleware(app *App, cfg auth.Config) router.MiddlewareFunc {
	return func(hf router.HandlerFunc) router.HandlerFunc {
		jwtConfig := jwtware.Config{
			ErrorHandler: app.auther.MakeClientRouteAuthErrorHandler(false),
			SigningKey: jwtware.SigningKey{
				Key:    []byte(cfg.GetSigningKey()),
				JWTAlg: cfg.GetSigningMethod(),
			},
			AuthScheme:  cfg.GetAuthScheme(),
			ContextKey:  cfg.GetContextKey(),
			TokenLookup: cfg.GetTokenLookup(),
			// Add TokenValidator - use the authenticator's token service if available
			TokenValidator: &TokenServiceAdapter{app.auth},
			// Template integration - automatic current_user injection
			TemplateUserKey: auth.TemplateUserKey,
			UserProvider: func(claims jwtware.AuthClaims) (any, error) {
				// Convert JWT claims to full User object for templates
				userID := claims.UserID()
				if userID == "" {
					app.GetLogger("jwt").Warn("Empty user ID in claims, using claims directly")
					return claims, nil // Fallback to claims
				}

				user, err := app.repo.Users().GetByID(context.Background(), userID)
				if err != nil {
					app.GetLogger("jwt").Warn("Failed to load user for template, using claims", "user_id", userID, "error", err)
					return claims, nil // Fallback to claims
				}

				app.GetLogger("jwt").Debug("Loaded user for template context", "user_id", userID, "username", user.Username)
				return user, nil
			},
		}

		return jwtware.New(jwtConfig)
	}
}

// TokenServiceAdapter adapts Authenticator to jwtware.TokenValidator interface
type TokenServiceAdapter struct {
	auth auth.Authenticator
}

// Validate implements the jwtware.TokenValidator interface
func (tsa *TokenServiceAdapter) Validate(tokenString string) (jwtware.AuthClaims, error) {
	// Use SessionFromToken to validate and get claims
	session, err := tsa.auth.SessionFromToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Convert Session to AuthClaims
	// Assuming the session has the necessary data, we create a basic claims object
	if authClaims, ok := session.(jwtware.AuthClaims); ok {
		return authClaims, nil
	}

	// If session doesn't implement AuthClaims, create a basic implementation
	return &auth.JWTClaims{
		UID:      session.GetUserID(),
		UserRole: session.GetData()["role"].(string),
	}, nil
}

// WebSocketTokenValidator implements the router.WSAuthClaims validation interface
type WebSocketTokenValidator struct {
	auth auth.Authenticator
}

// Validate validates a WebSocket token using our authenticator
func (w *WebSocketTokenValidator) Validate(tokenString string) (router.WSAuthClaims, error) {
	fmt.Printf("[DEBUG] WebSocketTokenValidator.Validate called with token length: %d\n", len(tokenString))
	session, err := w.auth.SessionFromToken(tokenString)
	if err != nil {
		fmt.Printf("[ERROR] WebSocketTokenValidator.Validate failed: %v\n", err)
		return nil, err
	}

	fmt.Printf("[DEBUG] WebSocketTokenValidator.Validate successful for user: %s\n", session.GetUserID())
	// Convert session to WebSocket claims
	return &WebSocketAuthClaims{session: session}, nil
}

// WebSocketAuthClaims adapts our session to WebSocket auth claims
type WebSocketAuthClaims struct {
	session auth.Session
}

func (w *WebSocketAuthClaims) UserID() string { return w.session.GetUserID() }
func (w *WebSocketAuthClaims) Role() string {
	if data := w.session.GetData(); data != nil {
		if role, ok := data["role"].(string); ok {
			return role
		}
	}
	return "user"
}
func (w *WebSocketAuthClaims) Subject() string          { return w.session.GetUserID() }
func (w *WebSocketAuthClaims) HasRole(role string) bool { return w.Role() == role }
func (w *WebSocketAuthClaims) IsAtLeast(minRole string) bool {
	currentRole := w.Role()
	return currentRole == "admin" || (currentRole == "moderator" && minRole == "user") || minRole == "user"
}
func (w *WebSocketAuthClaims) CanCreate(resource string) bool {
	return w.Role() == "admin" || w.Role() == "moderator"
}
func (w *WebSocketAuthClaims) CanRead(resource string) bool   { return true }
func (w *WebSocketAuthClaims) CanEdit(resource string) bool   { return w.Role() == "admin" }
func (w *WebSocketAuthClaims) CanDelete(resource string) bool { return w.Role() == "admin" }

// handleChatMessage processes chat messages from authenticated users
func handleChatMessage(ctx context.Context, client router.WSClient, claims router.WSAuthClaims, eventData any, app *App) error {
	// Check if user can send messages
	if !claims.CanCreate("chat_messages") {
		client.SendJSON(map[string]string{
			"type":    "error",
			"message": "Not authorized to send messages",
		})
		return nil
	}

	messageData, ok := eventData.(map[string]any)
	if !ok {
		app.GetLogger("websocket").Error("Invalid chat message data format")
		return nil
	}

	// Broadcast message to all users
	response := map[string]any{
		"type":      "new_message",
		"user_id":   claims.UserID(),
		"role":      claims.Role(),
		"message":   messageData["text"],
		"timestamp": time.Now().Format(time.RFC3339),
	}

	client.Room("users").Emit("message", response)
	app.GetLogger("websocket").Debug("Chat message broadcasted", "user_id", claims.UserID())
	return nil
}

// handleAdminCommand processes admin commands from authenticated admin users
// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleAdminCommand(ctx context.Context, client router.WSClient, claims router.WSAuthClaims, eventData any, app *App) error {
	// Check admin permissions
	if !claims.HasRole("admin") {
		client.SendJSON(map[string]string{
			"type":    "error",
			"message": "Admin privileges required",
		})
		return nil
	}

	commandData, ok := eventData.(map[string]any)
	if !ok {
		app.GetLogger("websocket").Error("Invalid admin command data format")
		return nil
	}

	command, ok := commandData["command"].(string)
	if !ok {
		app.GetLogger("websocket").Error("Missing command in admin command data")
		return nil
	}

	app.GetLogger("websocket").Info("Admin command executed", "user_id", claims.UserID(), "command", command)

	// Broadcast admin notification
	client.Room("users").Emit("admin_announcement", map[string]any{
		"type":      "admin_announcement",
		"message":   fmt.Sprintf("Admin executed: %s", command),
		"admin_id":  claims.UserID(),
		"timestamp": time.Now().Format(time.RFC3339),
	})

	return nil
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

	// Add authentication template helpers globally
	vcfg.SetTemplateFunctions(auth.TemplateHelpers())

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
			"message": `<p>This is your Home Page</p><a href="/me">Profile</a> | <a href="/websocket-demo">WebSocket Demo</a>`,
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

	userProvider := auth.NewUserProvider(repo.Users())
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
			return c.Render("errors/500", router.ViewContext{
				"message": err.Error(),
			})
		}

		// Simplified - current_user automatically available from JWT middleware!
		app.GetLogger("profile").Debug("Rendering profile with automatic current_user injection",
			"user_id", session.GetUserID())

		return c.Render("profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
			// current_user automatically injected by JWT middleware
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

		// Simplified - current_user automatically available from JWT middleware!
		return c.Render("profile", router.ViewContext{
			"errors": nil,
			"record": NewUserDTO(user),
			// current_user automatically injected by JWT middleware
		})
	}
}
