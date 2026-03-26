package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const cookieName = "konfig_session"
const tokenTTL = 7 * 24 * time.Hour

type Claims struct {
	UserID       string       `json:"user_id"`
	Email        string       `json:"email"`
	Role         Role         `json:"role"`
	AccountType  AccountType  `json:"account_type,omitempty"`
	OrgID        string       `json:"org_id,omitempty"`
	MemberStatus MemberStatus `json:"member_status,omitempty"`
	jwt.RegisteredClaims
}

func CreateToken(user *User, secret string) (string, error) {
	claims := &Claims{
		UserID:       user.ID,
		Email:        user.Email,
		Role:         user.Role,
		AccountType:  user.AccountType,
		OrgID:        user.OrgID,
		MemberStatus: user.MemberStatus,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func ValidateToken(tokenStr, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func CookieName() string        { return cookieName }
func CookieTTL() time.Duration  { return tokenTTL }
