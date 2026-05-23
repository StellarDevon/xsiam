package auth

import (
	"context"
	"errors"
	"fmt"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/svcclient"

	"golang.org/x/crypto/bcrypt"
)

type LoginResp struct {
	Token        string      `json:"token"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	User         *model.User `json:"user"`
}

type AuthService struct {
	svcClient svcclient.Caller
	userRepo  *repository.UserRepo
}

func NewAuthService(svcClient svcclient.Caller, userRepo *repository.UserRepo) *AuthService {
	return &AuthService{svcClient: svcClient, userRepo: userRepo}
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResp, error) {
	token, err := s.svcClient.Login(ctx, email, password)
	if err != nil {
		return nil, err
	}
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = ""
	return &LoginResp{Token: token, User: user}, nil
}

// UserStore is the minimal interface UserService needs from the user repository.
type UserStore interface {
	List(ctx context.Context, tenantID string, page, pageSize int) ([]model.User, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Create(ctx context.Context, user *model.User) error
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
}

type UserService struct {
	userRepo UserStore
}

func NewUserService(userRepo *repository.UserRepo) *UserService {
	return &UserService{userRepo: userRepo}
}

// NewUserServiceWith accepts any UserStore (used in tests).
func NewUserServiceWith(userRepo UserStore) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.User, model.PageMeta, error) {
	return s.userRepo.List(ctx, tenantID, page, pageSize)
}

func (s *UserService) Get(ctx context.Context, key string) (*model.User, error) {
	return s.userRepo.GetByID(ctx, key)
}

func (s *UserService) Create(ctx context.Context, user *model.User, _ string) error {
	if user.PasswordHash != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.PasswordHash = string(hash)
	}
	user.IsEnabled = true
	return s.userRepo.Create(ctx, user)
}

func (s *UserService) Update(ctx context.Context, key string, patch map[string]any) error {
	if pw, ok := patch["password"]; ok {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw.(string)), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		delete(patch, "password")
		patch["password_hash"] = string(hash)
	}
	return s.userRepo.Update(ctx, key, patch)
}

func (s *UserService) Delete(ctx context.Context, key string) error {
	return s.userRepo.Delete(ctx, key)
}

func (s *UserService) ChangePassword(ctx context.Context, key, oldPw, newPw string) error {
	user, err := s.userRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPw)); err != nil {
		return errors.New("invalid current password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.userRepo.Update(ctx, key, map[string]any{"password_hash": string(hash)})
}

type TenantService struct {
	tenantRepo *repository.TenantRepo
}

func NewTenantService(tenantRepo *repository.TenantRepo) *TenantService {
	return &TenantService{tenantRepo: tenantRepo}
}

func (s *TenantService) List(ctx context.Context, page, pageSize int) ([]model.Tenant, model.PageMeta, error) {
	return s.tenantRepo.List(ctx, page, pageSize)
}

func (s *TenantService) Get(ctx context.Context, key string) (*model.Tenant, error) {
	return s.tenantRepo.GetByID(ctx, key)
}

func (s *TenantService) Create(ctx context.Context, tenant *model.Tenant, _ string) error {
	if tenant.Tier == "" {
		tenant.Tier = model.TenantTierChild
	}
	tenant.IsEnabled = true
	return s.tenantRepo.Create(ctx, tenant)
}

func (s *TenantService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.tenantRepo.Update(ctx, key, patch)
}

func (s *TenantService) Delete(ctx context.Context, key string) error {
	return s.tenantRepo.Delete(ctx, key)
}

type RBACService struct {
	roleRepo *repository.RBACRoleRepo
}

func NewRBACService(roleRepo *repository.RBACRoleRepo) *RBACService {
	return &RBACService{roleRepo: roleRepo}
}

func (s *RBACService) List(ctx context.Context, tenantID string) ([]model.RBACRole, error) {
	return s.roleRepo.List(ctx, tenantID)
}

func (s *RBACService) Create(ctx context.Context, role *model.RBACRole, _ string) error {
	if role.IsBuiltin {
		return fmt.Errorf("cannot create builtin role via API")
	}
	return s.roleRepo.Create(ctx, role)
}

func (s *RBACService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.roleRepo.Update(ctx, key, patch)
}

func (s *RBACService) Delete(ctx context.Context, key string) error {
	return s.roleRepo.Delete(ctx, key)
}

func (s *RBACService) AddMember(ctx context.Context, roleKey, userID string) error {
	roles, err := s.roleRepo.List(ctx, "")
	if err != nil {
		return err
	}
	for _, r := range roles {
		if r.Key == roleKey {
			for _, m := range r.Members {
				if m == userID {
					return nil
				}
			}
			return s.roleRepo.Update(ctx, roleKey, map[string]any{"members": append(r.Members, userID)})
		}
	}
	return fmt.Errorf("role %s not found", roleKey)
}

func (s *RBACService) RemoveMember(ctx context.Context, roleKey, userID string) error {
	roles, err := s.roleRepo.List(ctx, "")
	if err != nil {
		return err
	}
	for _, r := range roles {
		if r.Key == roleKey {
			var newMembers []string
			for _, m := range r.Members {
				if m != userID {
					newMembers = append(newMembers, m)
				}
			}
			return s.roleRepo.Update(ctx, roleKey, map[string]any{"members": newMembers})
		}
	}
	return fmt.Errorf("role %s not found", roleKey)
}
