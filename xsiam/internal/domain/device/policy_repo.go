package device

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAgentPolicies = "agent_policies"

// PolicyRepo is the ArangoDB-backed agent policy repository.
type PolicyRepo struct {
	db arangodb.Database
}

func NewPolicyRepo(db arangodb.Database) *PolicyRepo {
	return &PolicyRepo{db: db}
}

func (r *PolicyRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.AgentPolicy, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.AgentPolicy
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colAgentPolicies,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *PolicyRepo) GetByID(ctx context.Context, key string) (*model.AgentPolicy, error) {
	col, _ := r.db.Collection(ctx, colAgentPolicies)
	var policy model.AgentPolicy
	if _, err := col.ReadDocument(ctx, key, &policy); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("agent policy %s not found", key)
		}
		return nil, err
	}
	return &policy, nil
}

func (r *PolicyRepo) Create(ctx context.Context, policy *model.AgentPolicy) error {
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colAgentPolicies)
	meta, err := col.CreateDocument(ctx, policy)
	if err != nil {
		return err
	}
	policy.Key = meta.Key
	return nil
}

func (r *PolicyRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAgentPolicies)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *PolicyRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colAgentPolicies)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
