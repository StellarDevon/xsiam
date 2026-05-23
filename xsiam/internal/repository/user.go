package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colUsers = "users"

type UserRepo struct {
	db arangodb.Database
}

func NewUserRepo(db arangodb.Database) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.User, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.User
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colUsers,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *UserRepo) GetByID(ctx context.Context, key string) (*model.User, error) {
	col, _ := r.db.Collection(ctx, colUsers)
	var user model.User
	if _, err := col.ReadDocument(ctx, key, &user); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("user %s not found", key)
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, login string) (*model.User, error) {
	query := `FOR doc IN users FILTER doc.email == @login OR doc.username == @login LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"login": login},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, fmt.Errorf("user not found")
	}
	var user model.User
	_, err = cursor.ReadDocument(ctx, &user)
	return &user, err
}

func (r *UserRepo) Create(ctx context.Context, user *model.User) error {
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colUsers)
	meta, err := col.CreateDocument(ctx, user)
	if err != nil {
		return err
	}
	user.Key = meta.Key
	return nil
}

func (r *UserRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colUsers)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *UserRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colUsers)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
