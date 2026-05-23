package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colDetectionRules = "detection_rules"

type DetectionRuleRepo struct {
	db arangodb.Database
}

func NewDetectionRuleRepo(db arangodb.Database) *DetectionRuleRepo {
	return &DetectionRuleRepo{db: db}
}

type DetectionRuleListFilter struct {
	TenantID  string
	RuleType  string
	Status    string
	Keyword   string
	Page      int
	PageSize  int
	SortBy    string
	SortDesc  bool
}

func (r *DetectionRuleRepo) List(ctx context.Context, f DetectionRuleListFilter) ([]model.DetectionRule, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

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
	meta, err := FindPaged(ctx, r.db, ListOptions{
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

func (r *DetectionRuleRepo) GetByID(ctx context.Context, key string) (*model.DetectionRule, error) {
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

func (r *DetectionRuleRepo) FindByRuleID(ctx context.Context, ruleID string) (*model.DetectionRule, error) {
	query := `FOR doc IN detection_rules FILTER doc.rule_id == @ruleID LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"ruleID": ruleID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, fmt.Errorf("detection rule %s not found", ruleID)
	}
	var rule model.DetectionRule
	_, err = cursor.ReadDocument(ctx, &rule)
	return &rule, err
}

func (r *DetectionRuleRepo) Create(ctx context.Context, rule *model.DetectionRule) error {
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

func (r *DetectionRuleRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colDetectionRules)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *DetectionRuleRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colDetectionRules)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

func (r *DetectionRuleRepo) AggregateByMitre(ctx context.Context) (map[string][]string, error) {
	query := `
		FOR doc IN detection_rules
		FILTER doc.status == "active"
		COLLECT tactic = doc.mitre_tactic INTO techniques = doc.mitre_technique
		RETURN {tactic, techniques}
	`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	result := map[string][]string{}
	for cursor.HasMore() {
		var row struct {
			Tactic     string   `json:"tactic"`
			Techniques []string `json:"techniques"`
		}
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		result[row.Tactic] = row.Techniques
	}
	return result, nil
}

func (r *DetectionRuleRepo) UpdateStatus(ctx context.Context, key, status, operatorID string) error {
	return r.Update(ctx, key, map[string]any{model.FieldRuleStatus: status})
}
