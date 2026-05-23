package auth_test

import (
	"context"
	"testing"
	"xsiam/internal/domain/auth"
	"xsiam/internal/model"

	"golang.org/x/crypto/bcrypt"
)

// ── stub user repo ────────────────────────────────────────────────────────────

type stubUserRepo struct {
	users map[string]*model.User
	seq   int
}

func newStubUserRepo() *stubUserRepo {
	return &stubUserRepo{users: make(map[string]*model.User)}
}

func (r *stubUserRepo) Create(_ context.Context, u *model.User) error {
	r.seq++
	u.Key = "user-" + u.Email
	r.users[u.Key] = u
	return nil
}

func (r *stubUserRepo) GetByID(_ context.Context, key string) (*model.User, error) {
	return r.users[key], nil
}

func (r *stubUserRepo) GetByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (r *stubUserRepo) Update(_ context.Context, key string, patch map[string]any) error {
	u := r.users[key]
	if u == nil {
		return nil
	}
	if v, ok := patch["password_hash"]; ok {
		u.PasswordHash = v.(string)
	}
	if v, ok := patch["is_enabled"]; ok {
		u.IsEnabled = v.(bool)
	}
	return nil
}

func (r *stubUserRepo) Delete(_ context.Context, key string) error {
	delete(r.users, key)
	return nil
}

func (r *stubUserRepo) List(_ context.Context, tenantID string, _, _ int) ([]model.User, model.PageMeta, error) {
	var out []model.User
	for _, u := range r.users {
		if tenantID != "" && u.TenantID != tenantID {
			continue
		}
		out = append(out, *u)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestUserService_Create_HashesPassword(t *testing.T) {
	repo := newStubUserRepo()
	svc := auth.NewUserServiceWith(repo)

	u := &model.User{TenantID: "t-1", Email: "alice@x.com", PasswordHash: "plaintext"}
	if err := svc.Create(context.Background(), u, "op"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.PasswordHash == "plaintext" {
		t.Error("password should be hashed after Create")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("plaintext")); err != nil {
		t.Errorf("stored hash does not match original password: %v", err)
	}
}

func TestUserService_Create_SetsIsEnabled(t *testing.T) {
	repo := newStubUserRepo()
	svc := auth.NewUserServiceWith(repo)

	u := &model.User{TenantID: "t-1", Email: "bob@x.com"}
	_ = svc.Create(context.Background(), u, "op")
	if !u.IsEnabled {
		t.Error("new user should be enabled by default")
	}
}

func TestUserService_ChangePassword_RejectsWrongOldPassword(t *testing.T) {
	repo := newStubUserRepo()
	svc := auth.NewUserServiceWith(repo)

	u := &model.User{TenantID: "t-1", Email: "carol@x.com", PasswordHash: "secret"}
	_ = svc.Create(context.Background(), u, "op")

	err := svc.ChangePassword(context.Background(), u.Key, "wrong-old", "new-secret")
	if err == nil {
		t.Error("expected error for wrong old password")
	}
}

func TestUserService_ChangePassword_AcceptsCorrectOldPassword(t *testing.T) {
	repo := newStubUserRepo()
	svc := auth.NewUserServiceWith(repo)

	u := &model.User{TenantID: "t-1", Email: "dave@x.com", PasswordHash: "correct-old"}
	_ = svc.Create(context.Background(), u, "op")

	if err := svc.ChangePassword(context.Background(), u.Key, "correct-old", "new-password"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	updated, _ := repo.GetByID(context.Background(), u.Key)
	if err := bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-password")); err != nil {
		t.Errorf("new password hash does not match: %v", err)
	}
}

func TestUserService_Delete_RemovesUser(t *testing.T) {
	repo := newStubUserRepo()
	svc := auth.NewUserServiceWith(repo)

	u := &model.User{TenantID: "t-1", Email: "eve@x.com"}
	_ = svc.Create(context.Background(), u, "op")

	_ = svc.Delete(context.Background(), u.Key)

	got, _ := svc.Get(context.Background(), u.Key)
	if got != nil {
		t.Error("expected user to be deleted")
	}
}
