package repository

import (
	"context"
	"fmt"
	"sync/atomic"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

type ListOptions struct {
	Collection string
	Filters    []string
	BindVars   map[string]any
	SortBy     string
	SortDesc   bool
	Page       int
	PageSize   int
}

type listVersionCounter struct {
	v atomic.Int64
}

func (c *listVersionCounter) current() int64 { return c.v.Load() }
func (c *listVersionCounter) bump()          { c.v.Add(1) }

func FindPaged[T any](
	ctx context.Context,
	db arangodb.Database,
	opts ListOptions,
	out *[]T,
) (model.PageMeta, error) {
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PageSize < 1 {
		opts.PageSize = 20
	}
	if opts.PageSize > 100 {
		opts.PageSize = 100
	}

	offset := (opts.Page - 1) * opts.PageSize

	sortDir := "ASC"
	if opts.SortDesc {
		sortDir = "DESC"
	}
	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "created_at"
	}

	filterClause := ""
	for _, f := range opts.Filters {
		filterClause += " FILTER " + f
	}

	countAQL := fmt.Sprintf(
		`FOR doc IN %s%s COLLECT WITH COUNT INTO total RETURN total`,
		opts.Collection, filterClause,
	)
	pageAQL := fmt.Sprintf(
		`FOR doc IN %s%s SORT doc.%s %s LIMIT @offset, @limit RETURN doc`,
		opts.Collection, filterClause, sortBy, sortDir,
	)

	if opts.BindVars == nil {
		opts.BindVars = map[string]any{}
	}
	opts.BindVars["offset"] = offset
	opts.BindVars["limit"] = opts.PageSize

	countVars := map[string]any{}
	for k, v := range opts.BindVars {
		if k != "offset" && k != "limit" {
			countVars[k] = v
		}
	}

	cCursor, err := db.Query(ctx, countAQL, &arangodb.QueryOptions{BindVars: countVars})
	if err != nil {
		return model.PageMeta{}, fmt.Errorf("count query: %w", err)
	}
	defer cCursor.Close()
	var total int64
	if cCursor.HasMore() {
		if _, err = cCursor.ReadDocument(ctx, &total); err != nil {
			return model.PageMeta{}, fmt.Errorf("count read: %w", err)
		}
	}

	cursor, err := db.Query(ctx, pageAQL, &arangodb.QueryOptions{BindVars: opts.BindVars})
	if err != nil {
		return model.PageMeta{}, fmt.Errorf("page query: %w", err)
	}
	defer cursor.Close()

	for cursor.HasMore() {
		var doc T
		if _, err = cursor.ReadDocument(ctx, &doc); err != nil {
			return model.PageMeta{}, fmt.Errorf("page read: %w", err)
		}
		*out = append(*out, doc)
	}

	pages := int(total) / opts.PageSize
	if int(total)%opts.PageSize > 0 {
		pages++
	}

	return model.PageMeta{Total: total, Page: opts.Page, PageSize: opts.PageSize, Pages: pages}, nil
}
