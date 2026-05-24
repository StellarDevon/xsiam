package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const colETLRules = "etl_rules"

// ETLRuleRepo provides CRUD access to the etl_rules ArangoDB collection.
type ETLRuleRepo struct {
	db arangodb.Database
}

func NewETLRuleRepo(db arangodb.Database) *ETLRuleRepo {
	return &ETLRuleRepo{db: db}
}

// ETLRuleListFilter controls which rules are returned by List().
type ETLRuleListFilter struct {
	TenantID  string
	IsEnabled *bool  // nil = all, true/false = filter by enabled state
	Dataset   string // return only rules that include this dataset in match.dataset
	Page      int
	PageSize  int
}

// List returns paginated ETL rules matching the given filters.
func (r *ETLRuleRepo) List(ctx context.Context, f ETLRuleListFilter) ([]model.ETLRule, model.PageMeta, error) {
	filters := []string{}
	bindVars := map[string]any{}

	if f.TenantID != "" {
		filters = append(filters, "doc.tenant_id == @tenant_id")
		bindVars["tenant_id"] = f.TenantID
	}
	if f.IsEnabled != nil {
		filters = append(filters, "doc.is_enabled == @is_enabled")
		bindVars["is_enabled"] = *f.IsEnabled
	}
	// Dataset filter: rule applies if match.dataset is empty (wildcard) OR contains the value
	if f.Dataset != "" {
		filters = append(filters,
			`(LENGTH(doc.match.dataset) == 0 OR @dataset IN doc.match.dataset)`)
		bindVars["dataset"] = f.Dataset
	}

	var rules []model.ETLRule
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colETLRules,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     "priority",
		SortDesc:   false,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &rules)
	if err != nil {
		return nil, model.PageMeta{}, fmt.Errorf("etl_rule list: %w", err)
	}
	return rules, meta, nil
}

// GetByKey reads one rule by ArangoDB _key.
func (r *ETLRuleRepo) GetByKey(ctx context.Context, key string) (*model.ETLRule, error) {
	col, err := r.db.Collection(ctx, colETLRules)
	if err != nil {
		return nil, fmt.Errorf("etl_rules collection: %w", err)
	}
	var rule model.ETLRule
	if _, err := col.ReadDocument(ctx, key, &rule); err != nil {
		return nil, fmt.Errorf("etl_rule get: %w", err)
	}
	return &rule, nil
}

// FindByRuleID looks up a rule by its human-readable rule_id field.
func (r *ETLRuleRepo) FindByRuleID(ctx context.Context, ruleID string) (*model.ETLRule, error) {
	aql := `FOR doc IN etl_rules FILTER doc.rule_id == @rule_id LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"rule_id": ruleID},
	})
	if err != nil {
		return nil, fmt.Errorf("etl_rule find by rule_id: %w", err)
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, nil // not found
	}
	var rule model.ETLRule
	if _, err = cursor.ReadDocument(ctx, &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// FindEnabledForTenant returns all enabled rules for the given tenant,
// sorted by priority ASC. Called by the ETL RuleEngine at startup and every 60s.
// Pass tenantID="" to load rules for all tenants (useful for super-admin or single-tenant mode).
func (r *ETLRuleRepo) FindEnabledForTenant(ctx context.Context, tenantID string) ([]model.ETLRule, error) {
	var aql string
	var bindVars map[string]any

	if tenantID == "" {
		// Load all enabled rules across all tenants, sorted by priority
		aql = `FOR doc IN etl_rules
			     FILTER doc.is_enabled == true
			     SORT doc.priority ASC
			     RETURN doc`
		bindVars = map[string]any{}
	} else {
		aql = `FOR doc IN etl_rules
			     FILTER doc.tenant_id == @tenant_id AND doc.is_enabled == true
			     SORT doc.priority ASC
			     RETURN doc`
		bindVars = map[string]any{"tenant_id": tenantID}
	}

	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		return nil, fmt.Errorf("etl_rule find enabled: %w", err)
	}
	defer cursor.Close()

	var rules []model.ETLRule
	for cursor.HasMore() {
		var rule model.ETLRule
		if _, err = cursor.ReadDocument(ctx, &rule); err != nil {
			return nil, fmt.Errorf("etl_rule read: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Create inserts a new ETL rule.
func (r *ETLRuleRepo) Create(ctx context.Context, rule *model.ETLRule) error {
	col, err := r.db.Collection(ctx, colETLRules)
	if err != nil {
		return fmt.Errorf("etl_rules collection: %w", err)
	}
	meta, err := col.CreateDocument(ctx, rule)
	if err != nil {
		return fmt.Errorf("etl_rule create: %w", err)
	}
	rule.Key = meta.Key
	return nil
}

// Update applies a partial patch (map) to the rule identified by key.
// Always sets updated_at to now.
func (r *ETLRuleRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	col, err := r.db.Collection(ctx, colETLRules)
	if err != nil {
		return fmt.Errorf("etl_rules collection: %w", err)
	}
	patch["updated_at"] = time.Now().UTC()
	if _, err := col.UpdateDocument(ctx, key, patch); err != nil {
		return fmt.Errorf("etl_rule update: %w", err)
	}
	return nil
}

// Delete removes the ETL rule with the given ArangoDB _key.
func (r *ETLRuleRepo) Delete(ctx context.Context, key string) error {
	col, err := r.db.Collection(ctx, colETLRules)
	if err != nil {
		return fmt.Errorf("etl_rules collection: %w", err)
	}
	if _, err := col.DeleteDocument(ctx, key); err != nil {
		return fmt.Errorf("etl_rule delete: %w", err)
	}
	return nil
}
