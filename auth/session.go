package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var _ Session = &SessionObject{}

type SessionObject struct {
	UserID         string         `json:"user_id,omitempty"`
	Audience       []string       `json:"audience,omitempty"`
	Issuer         string         `json:"issuer,omitempty"`
	IssuedAt       *time.Time     `json:"issued_at,omitempty"`
	ExpirationDate *time.Time     `json:"expiration_date,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}

func (s *SessionObject) GetUserID() string {
	return s.UserID
}

func (s *SessionObject) GetUserUUID() (uuid.UUID, error) {
	return uuid.Parse(s.UserID)
}

func (s *SessionObject) GetAudience() []string {
	return s.Audience
}

func (s *SessionObject) GetIssuer() string {
	return s.Issuer
}

func (s *SessionObject) GetIssuedAt() *time.Time {
	return s.IssuedAt
}

func (s *SessionObject) GetData() map[string]any {
	return s.Data
}

// TODO: enable only in development!
func (s SessionObject) String() string {
	return fmt.Sprintf(
		"user=%s aud=%v iss=%s iat=%s data=%v",
		s.UserID,
		s.Audience,
		s.Issuer,
		s.IssuedAt.Format(time.RFC1123),
		s.Data,
	)
}

func sessionFromClaims(claims jwt.Claims) (*SessionObject, error) {
	sub, err := claims.GetSubject()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	iss, err := claims.GetIssuer()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	eat, err := claims.GetExpirationTime()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		return nil, ErrUnableToParseData
	}

	dat, err := getData(claims)
	if err != nil {
		return nil, ErrUnableToParseData
	}

	return &SessionObject{
		UserID:         sub,
		Audience:       aud,
		Issuer:         iss,
		Data:           dat,
		IssuedAt:       &iat.Time,
		ExpirationDate: &eat.Time,
	}, nil
}

func getData(claims jwt.Claims) (map[string]any, error) {
	mp, ok := claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrUnableToMapClaims
	}

	d, ok := mp["dat"]
	if !ok {
		return nil, ErrUnableToMapClaims
	}

	dat, ok := d.(map[string]any)
	if !ok {
		return nil, ErrUnableToMapClaims
	}
	return dat, nil
}
