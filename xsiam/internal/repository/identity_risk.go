package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colIdentityRisks = "identity_risks"

type IdentityRiskRepo struct {
	db arangodb.Database
}

func NewIdentityRiskRepo(db arangodb.Database) *IdentityRiskRepo {
	return &IdentityRiskRepo{db: db}
}

func (r *IdentityRiskRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.IdentityRisk, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.IdentityRisk
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colIdentityRisks,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     "risk_score",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *IdentityRiskRepo) GetByUserID(ctx context.Context, userID string) (*model.IdentityRisk, error) {
	query := `FOR doc IN identity_risks FILTER doc.user_id == @userID LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"userID": userID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, nil
	}
	var risk model.IdentityRisk
	_, err = cursor.ReadDocument(ctx, &risk)
	return &risk, err
}

func (r *IdentityRiskRepo) GetByKey(ctx context.Context, key string) (*model.IdentityRisk, error) {
	col, _ := r.db.Collection(ctx, colIdentityRisks)
	var risk model.IdentityRisk
	if _, err := col.ReadDocument(ctx, key, &risk); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("identity risk %s not found", key)
		}
		return nil, err
	}
	return &risk, nil
}

func (r *IdentityRiskRepo) Upsert(ctx context.Context, risk *model.IdentityRisk) error {
	col, err := r.db.Collection(ctx, colIdentityRisks)
	if err != nil {
		return fmt.Errorf("get collection %s: %w", colIdentityRisks, err)
	}
	existing, _ := r.GetByUserID(ctx, risk.UserID)
	if existing == nil {
		risk.CreatedAt = time.Now()
		risk.UpdatedAt = time.Now()
		meta, err := col.CreateDocument(ctx, risk)
		if err != nil {
			return err
		}
		risk.Key = meta.Key
		return nil
	}
	patch := map[string]any{
		"risk_score":   risk.RiskScore,
		"risk_signals": risk.RiskSignals,
		"updated_at":   time.Now(),
	}
	_, err = col.UpdateDocument(ctx, existing.Key, patch)
	return err
}

// CountByTenant returns the total number of identity risks for the given tenant.
func (r *IdentityRiskRepo) CountByTenant(ctx context.Context, tenantID string) (int64, error) {
	query := `FOR doc IN identity_risks FILTER doc.tenant_id == @tid COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		if _, err = cursor.ReadDocument(ctx, &n); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (r *IdentityRiskRepo) ListAll(ctx context.Context) ([]model.IdentityRisk, error) {
	query := `FOR doc IN identity_risks RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.IdentityRisk
	for cursor.HasMore() {
		var risk model.IdentityRisk
		if _, err = cursor.ReadDocument(ctx, &risk); err != nil {
			return nil, err
		}
		results = append(results, risk)
	}
	return results, nil
}
