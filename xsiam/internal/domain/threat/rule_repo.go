package threat

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colDetectionRules = "detection_rules"

// RuleRepo is the ArangoDB-backed detection rule repository.
type RuleRepo struct {
	db arangodb.Database
}

func NewRuleRepo(db arangodb.Database) *RuleRepo {
	return &RuleRepo{db: db}
}

func (r *RuleRepo) List(ctx context.Context, f repository.DetectionRuleListFilter) ([]model.DetectionRule, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.RuleType != "" {
		filters = append(filters, "doc.rule_type == @ruleType")
		bindVars["ruleType"] = f.RuleType
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	var data []model.DetectionRule
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colDetectionRules,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *RuleRepo) GetByID(ctx context.Context, key string) (*model.DetectionRule, error) {
	col, _ := r.db.Collection(ctx, colDetectionRules)
	var rule model.DetectionRule
	if _, err := col.ReadDocument(ctx, key, &rule); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("detection rule %s not found", key)
		}
		return nil, err
	}
	return &rule, nil
}

func (r *RuleRepo) Create(ctx context.Context, rule *model.DetectionRule) error {
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colDetectionRules)
	meta, err := col.CreateDocument(ctx, rule)
	if err != nil {
		return err
	}
	rule.Key = meta.Key
	return nil
}

func (r *RuleRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colDetectionRules)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *RuleRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colDetectionRules)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

func (r *RuleRepo) AggregateByMitre(ctx context.Context, tenantID string) (map[string]int, error) {
	query := `
		FOR r IN detection_rules
		  FILTER r.tenant_id == @tenant_id AND r.status IN ["active", "testing"]
		  FOR tactic IN (r.mitre_tactics || [r.mitre_tactic])
		    FILTER tactic != null AND tactic != ""
		    COLLECT t = tactic WITH COUNT INTO n
		    RETURN {tactic: t, count: n}
	`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenant_id": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	result := map[string]int{}
	for cursor.HasMore() {
		var row struct {
			Tactic string `json:"tactic"`
			Count  int    `json:"count"`
		}
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		result[row.Tactic] = row.Count
	}
	return result, nil
}

func (r *RuleRepo) UpdateStatus(ctx context.Context, key, status, operatorID string) error {
	return r.Update(ctx, key, map[string]any{model.FieldRuleStatus: status})
}
