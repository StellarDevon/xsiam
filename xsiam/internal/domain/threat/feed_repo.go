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

const colIntelFeeds = "intel_feeds"

// FeedRepo is the ArangoDB-backed intel feed repository.
type FeedRepo struct {
	db arangodb.Database
}

func NewFeedRepo(db arangodb.Database) *FeedRepo {
	return &FeedRepo{db: db}
}

type FeedListFilter struct {
	TenantID string
	Keyword  string
	FeedType string
	Status   string
	Page     int
	PageSize int
}

func (r *FeedRepo) List(ctx context.Context, f FeedListFilter) ([]model.IntelFeed, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}
	if f.FeedType != "" {
		filters = append(filters, "doc.feed_type == @feedType")
		bindVars["feedType"] = f.FeedType
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}

	var data []model.IntelFeed
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colIntelFeeds,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *FeedRepo) GetByID(ctx context.Context, key string) (*model.IntelFeed, error) {
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

func (r *FeedRepo) Create(ctx context.Context, feed *model.IntelFeed) error {
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

func (r *FeedRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colIntelFeeds)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *FeedRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colIntelFeeds)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
