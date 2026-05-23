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

const colActions = "actions"

// ActionRepo is the ArangoDB-backed action repository.
type ActionRepo struct {
	db arangodb.Database
}

func NewActionRepo(db arangodb.Database) *ActionRepo {
	return &ActionRepo{db: db}
}

func (r *ActionRepo) List(ctx context.Context, f repository.ActionListFilter) ([]model.Action, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}
	if f.IncidentID != "" {
		filters = append(filters, "doc.incident_id == @incidentId")
		bindVars["incidentId"] = f.IncidentID
	}

	var data []model.Action
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colActions,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *ActionRepo) GetByID(ctx context.Context, key string) (*model.Action, error) {
	col, _ := r.db.Collection(ctx, colActions)
	var action model.Action
	if _, err := col.ReadDocument(ctx, key, &action); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("action %s not found", key)
		}
		return nil, err
	}
	return &action, nil
}

func (r *ActionRepo) Create(ctx context.Context, action *model.Action) error {
	now := time.Now()
	action.CreatedAt = now
	action.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colActions)
	meta, err := col.CreateDocument(ctx, action)
	if err != nil {
		return err
	}
	action.Key = meta.Key
	return nil
}

func (r *ActionRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colActions)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
