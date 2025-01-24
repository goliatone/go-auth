package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var _ Session = session{}

type session struct {
	userID         string
	audience       []string
	issuer         string
	issuedAt       *time.Time
	expirationDate *time.Time
	data           map[string]any
}

func (s session) UserID() string {
	return s.userID
}

func (s session) UserUUID() (uuid.UUID, error) {
	return uuid.Parse(s.userID)
}

func (s session) Audience() []string {
	return s.audience
}

func (s session) Issuer() string {
	return s.issuer
}

func (s session) IssuedAt() *time.Time {
	return s.issuedAt
}

func (s session) Data() map[string]any {
	return s.data
}

// TODO: enable only in development!
func (s session) String() string {
	return fmt.Sprintf(
		"user=%s aud=%v iss=%s iat=%s data=%v",
		s.userID,
		s.audience,
		s.issuer,
		s.issuedAt.Format(time.RFC1123),
		s.data,
	)
}

func sessionFromClaims(claims jwt.Claims) (Session, error) {
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

	return session{
		userID:         sub,
		audience:       aud,
		issuer:         iss,
		data:           dat,
		issuedAt:       &iat.Time,
		expirationDate: &eat.Time,
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
