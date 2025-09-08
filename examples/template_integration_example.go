package main

import (
	"fmt"
	"log"

	"github.com/goliatone/go-auth"
	"github.com/goliatone/go-template"
	"github.com/google/uuid"
)

func main() {
	// Example 1: Basic usage with TemplateHelpers
	fmt.Println("=== Example 1: Basic Template Helpers ===")
	renderer1, err := template.NewRenderer(
		template.WithBaseDir("/tmp"), // Using /tmp for this example
		template.WithGlobalData(auth.TemplateHelpers()),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a user for testing
	adminUser := &auth.User{
		ID:        uuid.New(),
		Role:      auth.RoleAdmin,
		FirstName: "Jane",
		LastName:  "Doe",
		Username:  "janedoe",
		Email:     "jane@example.com",
	}

	// Example template showing role checks
	template1 := `
Welcome{% if current_user %}, {{ current_user.first_name }}{% endif %}!

{% if current_user|is_authenticated %}
  Your role: {{ current_user.user_role }}
  
  {% if current_user|has_role:"admin" %}
    <div class="admin-panel">
      <h3>Admin Panel</h3>
      <p>You have admin privileges!</p>
    </div>
  {% endif %}
  
  {% if current_user|can_create %}
    <a href="/posts/new" class="btn">Create New Post</a>
  {% endif %}
  
  {% if current_user|can_edit %}
    <a href="/posts/edit" class="btn">Edit Posts</a>
  {% endif %}
  
  {% if current_user|can_delete %}
    <a href="/posts/delete" class="btn btn-danger">Delete Posts</a>
  {% else %}
    <p class="text-muted">You don't have delete permissions.</p>
  {% endif %}
{% else %}
  <p>Please <a href="/login">login</a> to continue.</p>
{% endif %}`

	result1, err := renderer1.RenderString(template1, map[string]any{
		"current_user": adminUser,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result1)
	fmt.Println()

	// Example 2: Using TemplateHelpersWithUser for global user context
	fmt.Println("=== Example 2: Template Helpers with Global User ===")
	renderer2, err := template.NewRenderer(
		template.WithBaseDir("/tmp"),
		template.WithGlobalData(auth.TemplateHelpersWithUser(adminUser)),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Template that uses globally available current_user
	template2 := `
<nav class="navbar">
  {% if current_user|is_authenticated %}
    <span class="user-info">
      Hello, {{ current_user.first_name }}! 
      ({{ current_user.user_role|title }})
    </span>
    
    <ul class="nav-menu">
      <li><a href="/dashboard">Dashboard</a></li>
      
      {% if current_user|is_at_least:"member" %}
        <li><a href="/profile">My Profile</a></li>
      {% endif %}
      
      {% if current_user|can_access:"create" %}
        <li><a href="/posts/create">Create Post</a></li>
      {% endif %}
      
      {% if current_user|has_role:"admin" %}
        <li><a href="/admin">Admin</a></li>
      {% endif %}
      
      {% if current_user|has_role:"owner" %}
        <li><a href="/system">System Settings</a></li>
      {% endif %}
    </ul>
    
    <a href="/logout" class="logout-btn">Logout</a>
  {% else %}
    <div class="auth-buttons">
      <a href="/login" class="btn btn-primary">Login</a>
      <a href="/register" class="btn btn-secondary">Register</a>
    </div>
  {% endif %}
</nav>`

	result2, err := renderer2.RenderString(template2, map[string]any{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result2)
	fmt.Println()

	// Example 3: Different user roles
	fmt.Println("=== Example 3: Different User Roles ===")
	
	users := []*auth.User{
		{Role: auth.RoleGuest, FirstName: "Guest", Username: "guest"},
		{Role: auth.RoleMember, FirstName: "Member", Username: "member"},
		{Role: auth.RoleAdmin, FirstName: "Admin", Username: "admin"},
		{Role: auth.RoleOwner, FirstName: "Owner", Username: "owner"},
	}

	permissionTemplate := `
User: {{ user.first_name }} ({{ user.user_role }})
Permissions:
  - Read: {{ user|can_read }}
  - Edit: {{ user|can_edit }}  
  - Create: {{ user|can_create }}
  - Delete: {{ user|can_delete }}
  - Is at least Member: {{ user|is_at_least:"member" }}
  - Has Admin role: {{ user|has_role:"admin" }}
---`

	renderer3, err := template.NewRenderer(
		template.WithBaseDir("/tmp"),
		template.WithGlobalData(auth.TemplateHelpers()),
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, user := range users {
		result, err := renderer3.RenderString(permissionTemplate, map[string]any{
			"user": user,
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
	}

	// Example 4: Using role constants
	fmt.Println("=== Example 4: Role Constants ===")
	roleTemplate := `
Available roles in the system:
{% for role_name, role_value in roles %}
  - {{ role_name|title }}: {{ role_value }}
{% endfor %}

Current user role matches admin: {{ current_user.user_role == roles.admin }}
Current user role matches owner: {{ current_user.user_role == roles.owner }}`

	result4, err := renderer2.RenderString(roleTemplate, map[string]any{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result4)
	fmt.Println()

	fmt.Println("=== Integration Complete ===")
	fmt.Println("The go-auth template helpers are now ready to use with go-template!")
	fmt.Println()
	fmt.Println("Usage in your application:")
	fmt.Println("  import \"github.com/goliatone/go-auth\"")
	fmt.Println("  import \"github.com/goliatone/go-template\"")
	fmt.Println()
	fmt.Println("  // Basic helpers")
	fmt.Println("  renderer, _ := template.NewRenderer(")
	fmt.Println("    template.WithBaseDir(\"./templates\"),")
	fmt.Println("    template.WithGlobalData(auth.TemplateHelpers()),")
	fmt.Println("  )")
	fmt.Println()
	fmt.Println("  // With current user")
	fmt.Println("  renderer, _ := template.NewRenderer(")
	fmt.Println("    template.WithBaseDir(\"./templates\"),")
	fmt.Println("    template.WithGlobalData(auth.TemplateHelpersWithUser(currentUser)),")
	fmt.Println("  )")
}