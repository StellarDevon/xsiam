package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colPlaybooks = "playbooks"

type PlaybookRepo struct {
	db arangodb.Database
}

func NewPlaybookRepo(db arangodb.Database) *PlaybookRepo {
	return &PlaybookRepo{db: db}
}

func (r *PlaybookRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.Playbook, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.Playbook
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colPlaybooks,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
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
