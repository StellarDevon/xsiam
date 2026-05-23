package response

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colPlaybooks = "playbooks"

// PlaybookRepo is the ArangoDB-backed playbook repository.
type PlaybookRepo struct {
	db arangodb.Database
}

func NewPlaybookRepo(db arangodb.Database) *PlaybookRepo {
	return &PlaybookRepo{db: db}
}

type PlaybookListFilter struct {
	TenantID    string
	Keyword     string
	TriggerType string
	Status      string
	Page        int
	PageSize    int
}

func (r *PlaybookRepo) List(ctx context.Context, f PlaybookListFilter) ([]model.Playbook, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}
	if f.TriggerType != "" {
		filters = append(filters, "doc.trigger.type == @triggerType")
		bindVars["triggerType"] = f.TriggerType
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}

	var data []model.Playbook
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colPlaybooks,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *PlaybookRepo) GetByID(ctx context.Context, key string) (*model.Playbook, error) {
	col, _ := r.db.Collection(ctx, colPlaybooks)
	var pb model.Playbook
	if _, err := col.ReadDocument(ctx, key, &pb); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("playbook %s not found", key)
		}
		return nil, err
	}
	return &pb, nil
}

func (r *PlaybookRepo) Create(ctx context.Context, pb *model.Playbook) error {
	now := time.Now()
	pb.CreatedAt = now
	pb.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colPlaybooks)
	meta, err := col.CreateDocument(ctx, pb)
	if err != nil {
		return err
	}
	pb.Key = meta.Key
	return nil
}

func (r *PlaybookRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colPlaybooks)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *PlaybookRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colPlaybooks)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
