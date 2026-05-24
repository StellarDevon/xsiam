package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colPrivilegeRestrictions = "privilege_restrictions"

type PrivilegeRestrictionRepo struct {
	db arangodb.Database
}

func NewPrivilegeRestrictionRepo(db arangodb.Database) *PrivilegeRestrictionRepo {
	return &PrivilegeRestrictionRepo{db: db}
}

// List returns active privilege restrictions for a tenant.
// When userID is non-empty it further filters to that specific user.
func (r *PrivilegeRestrictionRepo) List(ctx context.Context, tenantID, userID string) ([]model.PrivilegeRestriction, error) {
	var query string
	bindVars := map[string]any{"tenantID": tenantID}

	if userID != "" {
		query = `FOR doc IN privilege_restrictions
		           FILTER doc.tenant_id == @tenantID
		             AND doc.user_id == @userID
		             AND doc.is_active == true
		           RETURN doc`
		bindVars["userID"] = userID
	} else {
		query = `FOR doc IN privilege_restrictions
		           FILTER doc.tenant_id == @tenantID
		             AND doc.is_active == true
		           RETURN doc`
	}

	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.PrivilegeRestriction
	for cursor.HasMore() {
		var pr model.PrivilegeRestriction
		if _, err = cursor.ReadDocument(ctx, &pr); err != nil {
			return nil, err
		}
		results = append(results, pr)
	}
	return results, nil
}

func (r *PrivilegeRestrictionRepo) GetActiveByUserLevel(ctx context.Context, userID string, level int) (*model.PrivilegeRestriction, error) {
	query := `FOR doc IN privilege_restrictions FILTER doc.user_id == @userID AND doc.level == @level AND doc.is_active == true LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"userID": userID, "level": level},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, nil
	}
	var restriction model.PrivilegeRestriction
	_, err = cursor.ReadDocument(ctx, &restriction)
	return &restriction, err
}

func (r *PrivilegeRestrictionRepo) GetByKey(ctx context.Context, key string) (*model.PrivilegeRestriction, error) {
	col, _ := r.db.Collection(ctx, colPrivilegeRestrictions)
	var restriction model.PrivilegeRestriction
	if _, err := col.ReadDocument(ctx, key, &restriction); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("privilege restriction %s not found", key)
		}
		return nil, err
	}
	return &restriction, nil
}

func (r *PrivilegeRestrictionRepo) Create(ctx context.Context, restriction *model.PrivilegeRestriction) error {
	restriction.AppliedAt = time.Now()
	restriction.IsActive = true
	col, _ := r.db.Collection(ctx, colPrivilegeRestrictions)
	meta, err := col.CreateDocument(ctx, restriction)
	if err != nil {
		return err
	}
	restriction.Key = meta.Key
	return nil
}

// ReleaseByUserID deactivates all active restrictions for userID within the given tenant.
func (r *PrivilegeRestrictionRepo) ReleaseByUserID(ctx context.Context, userID, tenantID string) error {
	now := time.Now()
	query := `FOR doc IN privilege_restrictions
	            FILTER doc.user_id == @userID
	              AND doc.tenant_id == @tenantID
	              AND doc.is_active == true
	            UPDATE doc WITH {is_active: false, released_at: @now} IN privilege_restrictions`
	_, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{
			"userID":   userID,
			"tenantID": tenantID,
			"now":      now,
		},
	})
	return err
}

// Delete removes a privilege restriction document by its _key.
func (r *PrivilegeRestrictionRepo) Delete(ctx context.Context, key string) error {
	col, err := r.db.Collection(ctx, colPrivilegeRestrictions)
	if err != nil {
		return err
	}
	_, err = col.DeleteDocument(ctx, key)
	if err != nil && shared.IsNotFound(err) {
		return fmt.Errorf("privilege restriction %s not found", key)
	}
	return err
}

// CountActive returns the number of currently active privilege restrictions for a tenant.
func (r *PrivilegeRestrictionRepo) CountActive(ctx context.Context, tenantID string) (int64, error) {
	query := `RETURN COUNT(FOR doc IN privilege_restrictions FILTER doc.tenant_id == @tenantID AND doc.is_active == true RETURN 1)`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return 0, nil
	}
	var count int64
	if _, err = cursor.ReadDocument(ctx, &count); err != nil {
		return 0, err
	}
	return count, nil
}
