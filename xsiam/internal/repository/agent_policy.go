package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAgentPolicies = "agent_policies"

type AgentPolicyRepo struct {
	db arangodb.Database
}

func NewAgentPolicyRepo(db arangodb.Database) *AgentPolicyRepo {
	return &AgentPolicyRepo{db: db}
}

func (r *AgentPolicyRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.AgentPolicy, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.AgentPolicy
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colAgentPolicies,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *AgentPolicyRepo) GetByID(ctx context.Context, key string) (*model.AgentPolicy, error) {
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

func (r *AgentPolicyRepo) Create(ctx context.Context, policy *model.AgentPolicy) error {
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

func (r *AgentPolicyRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAgentPolicies)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
