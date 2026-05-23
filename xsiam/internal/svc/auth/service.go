package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Claims represents the JWT payload.
type Claims struct {
	UID  string `json:"uid"`
	TID  string `json:"tid"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// Service issues and verifies JWTs.
type Service struct {
	secret    []byte
	expireHr  int
	userRepo  *repository.UserRepo
}

func New(secret string, expireHr int, userRepo *repository.UserRepo) *Service {
	if expireHr <= 0 {
		expireHr = 24
	}
	return &Service{secret: []byte(secret), expireHr: expireHr, userRepo: userRepo}
}

// isTransientDBError returns true for network/connection errors that may resolve on retry.
func isTransientDBError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset")
}

// Login validates credentials and returns a signed JWT.
func (s *Service) Login(ctx context.Context, email, password string) (string, *model.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil && isTransientDBError(err) {
		// Retry up to 3 times with 3s delay for transient DB errors (e.g. ArangoDB restart)
		for i := 0; i < 3; i++ {
			log.Printf("[auth] transient DB error (attempt %d/3), retrying in 3s: %v", i+1, err)
			time.Sleep(3 * time.Second)
			user, err = s.userRepo.GetByEmail(ctx, email)
			if err == nil || !isTransientDBError(err) {
				break
			}
		}
	}
	if err != nil {
		return "", nil, errors.New("invalid credentials")
	}
	if !user.IsEnabled {
		return "", nil, errors.New("account disabled")
	}
	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid credentials")
	}
	token, err := s.Issue(user.Key, user.TenantID, string(user.Role))
	if err != nil {
		return "", nil, fmt.Errorf("issue token: %w", err)
	}
	user.PasswordHash = ""
	return token, user, nil
}

// Issue creates and signs a JWT for the given user.
func (s *Service) Issue(uid, tid, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UID:  uid,
		TID:  tid,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(s.expireHr) * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// Verify parses and validates a JWT, returning the claims.
func (s *Service) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// Refresh validates an existing token and issues a new one with extended expiry.
func (s *Service) Refresh(tokenStr string) (string, error) {
	claims, err := s.Verify(tokenStr)
	if err != nil {
		return "", err
	}
	return s.Issue(claims.UID, claims.TID, claims.Role)
}
