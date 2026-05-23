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

func (r *PrivilegeRestrictionRepo) List(ctx context.Context, userID string) ([]model.PrivilegeRestriction, error) {
	query := `FOR doc IN privilege_restrictions FILTER doc.user_id == @userID AND doc.is_active == true RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"userID": userID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.PrivilegeRestriction
	for cursor.HasMore() {
		var r model.PrivilegeRestriction
		if _, err = cursor.ReadDocument(ctx, &r); err != nil {
			return nil, err
		}
		results = append(results, r)
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
	col, _ := r.db.Collection(ctx, colPrivilegeRestrictions)
	meta, err := col.CreateDocument(ctx, restriction)
	if err != nil {
		return err
	}
	restriction.Key = meta.Key
	return nil
}

func (r *PrivilegeRestrictionRepo) ReleaseByUserID(ctx context.Context, userID, operatorID string) error {
	now := time.Now()
	query := `FOR doc IN privilege_restrictions FILTER doc.user_id == @userID AND doc.is_active == true UPDATE doc WITH {is_active: false, released_at: @now, released_by: @operatorID} IN privilege_restrictions`
	_, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"userID": userID, "now": now, "operatorID": operatorID},
	})
	return err
}
