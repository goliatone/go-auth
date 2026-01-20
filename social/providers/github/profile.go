package github

import (
	"fmt"

	"github.com/goliatone/go-auth/social"
)

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Company   string `json:"company"`
	Blog      string `json:"blog"`
	Location  string `json:"location"`
	Bio       string `json:"bio"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func mapProfile(user *githubUser, email string, emailVerified bool) *social.SocialProfile {
	if user == nil {
		return nil
	}

	return &social.SocialProfile{
		ProviderUserID: fmtUserID(user.ID),
		Provider:       "github",
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           user.Name,
		Username:       user.Login,
		AvatarURL:      user.AvatarURL,
		ProfileURL:     user.HTMLURL,
		Raw: map[string]any{
			"id":         user.ID,
			"login":      user.Login,
			"name":       user.Name,
			"email":      email,
			"avatar_url": user.AvatarURL,
			"html_url":   user.HTMLURL,
			"company":    user.Company,
			"blog":       user.Blog,
			"location":   user.Location,
			"bio":        user.Bio,
		},
	}
}

func fmtUserID(id int64) string {
	return fmt.Sprintf("%d", id)
}
