package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const (
	colTenants   = "tenants"
	colRBACRoles = "rbac_roles"
)

type TenantRepo struct {
	db arangodb.Database
}

func NewTenantRepo(db arangodb.Database) *TenantRepo {
	return &TenantRepo{db: db}
}

func (r *TenantRepo) List(ctx context.Context, page, pageSize int) ([]model.Tenant, model.PageMeta, error) {
	var data []model.Tenant
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colTenants,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *TenantRepo) GetByID(ctx context.Context, key string) (*model.Tenant, error) {
	col, _ := r.db.Collection(ctx, colTenants)
	var tenant model.Tenant
	if _, err := col.ReadDocument(ctx, key, &tenant); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("tenant %s not found", key)
		}
		return nil, err
	}
	return &tenant, nil
}

func (r *TenantRepo) Create(ctx context.Context, tenant *model.Tenant) error {
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colTenants)
	meta, err := col.CreateDocument(ctx, tenant)
	if err != nil {
		return err
	}
	tenant.Key = meta.Key
	return nil
}

func (r *TenantRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colTenants)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *TenantRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colTenants)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

type RBACRoleRepo struct {
	db arangodb.Database
}

func NewRBACRoleRepo(db arangodb.Database) *RBACRoleRepo {
	return &RBACRoleRepo{db: db}
}

func (r *RBACRoleRepo) List(ctx context.Context, tenantID string) ([]model.RBACRole, error) {
	query := `FOR doc IN rbac_roles FILTER doc.tenant_id == @tenantID RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.RBACRole
	for cursor.HasMore() {
		var role model.RBACRole
		if _, err = cursor.ReadDocument(ctx, &role); err != nil {
			return nil, err
		}
		results = append(results, role)
	}
	return results, nil
}

func (r *RBACRoleRepo) Create(ctx context.Context, role *model.RBACRole) error {
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colRBACRoles)
	meta, err := col.CreateDocument(ctx, role)
	if err != nil {
		return err
	}
	role.Key = meta.Key
	return nil
}

func (r *RBACRoleRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colRBACRoles)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *RBACRoleRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colRBACRoles)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
