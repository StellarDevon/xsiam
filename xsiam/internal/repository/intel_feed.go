package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colIntelFeeds = "intel_feeds"

type IntelFeedRepo struct {
	db arangodb.Database
}

func NewIntelFeedRepo(db arangodb.Database) *IntelFeedRepo {
	return &IntelFeedRepo{db: db}
}

func (r *IntelFeedRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.IntelFeed, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.IntelFeed
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colIntelFeeds,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *IntelFeedRepo) GetByID(ctx context.Context, key string) (*model.IntelFeed, error) {
	col, _ := r.db.Collection(ctx, colIntelFeeds)
	var feed model.IntelFeed
	if _, err := col.ReadDocument(ctx, key, &feed); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("intel feed %s not found", key)
		}
		return nil, err
	}
	return &feed, nil
}

func (r *IntelFeedRepo) Create(ctx context.Context, feed *model.IntelFeed) error {
	now := time.Now()
	feed.CreatedAt = now
	feed.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colIntelFeeds)
	meta, err := col.CreateDocument(ctx, feed)
	if err != nil {
		return err
	}
	feed.Key = meta.Key
	return nil
}

func (r *IntelFeedRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colIntelFeeds)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
