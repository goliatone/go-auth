package google

import "github.com/goliatone/go-auth/social"

type googleUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

func mapProfile(info *googleUserInfo) *social.SocialProfile {
	if info == nil {
		return nil
	}

	return &social.SocialProfile{
		ProviderUserID: info.Sub,
		Provider:       "google",
		Email:          info.Email,
		EmailVerified:  info.EmailVerified,
		Name:           info.Name,
		FirstName:      info.GivenName,
		LastName:       info.FamilyName,
		AvatarURL:      info.Picture,
		Raw: map[string]any{
			"sub":            info.Sub,
			"email":          info.Email,
			"email_verified": info.EmailVerified,
			"name":           info.Name,
			"given_name":     info.GivenName,
			"family_name":    info.FamilyName,
			"picture":        info.Picture,
			"locale":         info.Locale,
		},
	}
}
