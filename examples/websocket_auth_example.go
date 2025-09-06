package main

import (
	"context"
	"log"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-router"
)

func main() {
	// Initialize your go-auth authenticator as usual
	auther := auth.NewAuthenticator(
		&myIdentityProvider{}, // your identity provider
		myConfig{},            // your auth config
	).WithLogger(&myLogger{})

	// Create WebSocket authentication middleware - that's it!
	wsAuthMiddleware := auther.NewWSAuthMiddleware()

	// Or with custom configuration
	wsAuthMiddlewareCustom := auther.NewWSAuthMiddleware(router.WSAuthConfig{
		// Custom token extractor (optional)
		TokenExtractor: func(ctx context.Context, client router.WSClient) (string, error) {
			// Custom logic to extract token from WebSocket context
			return client.Conn().Query("my_custom_token"), nil
		},
		// Skip auth for certain connections (optional)
		Skip: func(ctx context.Context, client router.WSClient) bool {
			return client.Conn().Query("skip_auth") == "true"
		},
		// Custom failure handler (optional)
		OnAuthFailure: func(ctx context.Context, client router.WSClient, err error) error {
			log.Printf("WebSocket auth failed for client %s: %v", client.ID(), err)
			client.Close(router.ClosePolicyViolation, "Custom auth failure message")
			return err
		},
	})

	// Chain middleware in the recommended order
	middleware := router.ChainWSMiddleware(
		router.NewWSRecover(), // Panic recovery (outermost)
		router.NewWSLogger(),  // Logging
		wsAuthMiddleware,      // Authentication (or wsAuthMiddlewareCustom)
		router.NewWSMetrics(), // Metrics
		router.NewWSRateLimit(), // Rate limiting (innermost)
	)

	// Create WebSocket handler with authentication
	wsHandler := middleware(func(ctx context.Context, client router.WSClient) error {
		// Access authenticated user claims from context
		claims, ok := auth.WSAuthClaimsFromContext(ctx)
		if !ok {
			log.Printf("No auth claims found - this shouldn't happen after authentication")
			return nil
		}

		log.Printf("Authenticated WebSocket connection from user: %s (role: %s)", 
			claims.UserID(), claims.Role())

		// Check permissions for specific resources
		if claims.CanRead("chat_messages") {
			log.Printf("User %s can read chat messages", claims.UserID())
		}

		if claims.CanCreate("chat_rooms") {
			log.Printf("User %s can create chat rooms", claims.UserID())
		}

		// Your WebSocket business logic here
		for {
			messageType, data, err := client.ReadMessage()
			if err != nil {
				log.Printf("Read error: %v", err)
				break
			}

			// Echo message back (example)
			if err := client.WriteMessage(messageType, data); err != nil {
				log.Printf("Write error: %v", err)
				break
			}
		}

		return nil
	})

	// Set up router with WebSocket endpoint
	app := router.New()
	app.Get("/ws", router.WebSocketHandler(wsHandler))

	log.Fatal(app.Listen(":8080"))
}

// Example implementations (you'd replace these with your actual implementations)
type myIdentityProvider struct{}
func (m *myIdentityProvider) VerifyIdentity(ctx context.Context, identifier, password string) (auth.Identity, error) {
	// Your identity verification logic
	return nil, nil
}
func (m *myIdentityProvider) FindIdentityByIdentifier(ctx context.Context, identifier string) (auth.Identity, error) {
	// Your identity lookup logic
	return nil, nil
}

type myConfig struct{}
func (m myConfig) GetSigningKey() string { return "your-signing-key" }
func (m myConfig) GetSigningMethod() string { return "HS256" }
func (m myConfig) GetContextKey() string { return "user" }
func (m myConfig) GetTokenExpiration() int { return 24 }
func (m myConfig) GetExtendedTokenDuration() int { return 168 }
func (m myConfig) GetTokenLookup() string { return "header:Authorization" }
func (m myConfig) GetAuthScheme() string { return "Bearer" }
func (m myConfig) GetIssuer() string { return "your-app" }
func (m myConfig) GetAudience() []string { return []string{"your-app"} }
func (m myConfig) GetRejectedRouteKey() string { return "rejected_route" }
func (m myConfig) GetRejectedRouteDefault() string { return "/" }

type myLogger struct{}
func (m *myLogger) Debug(format string, args ...any) { log.Printf("[DEBUG] "+format, args...) }
func (m *myLogger) Info(format string, args ...any) { log.Printf("[INFO] "+format, args...) }
func (m *myLogger) Warn(format string, args ...any) { log.Printf("[WARN] "+format, args...) }
func (m *myLogger) Error(format string, args ...any) { log.Printf("[ERROR] "+format, args...) }