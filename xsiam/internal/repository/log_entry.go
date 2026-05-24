package repository

import (
	"context"
	"fmt"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const logEntriesCollection = "log_entries"

type LogEntryRepo struct {
	db arangodb.Database
}

func NewLogEntryRepo(db arangodb.Database) *LogEntryRepo {
	return &LogEntryRepo{db: db}
}

// Create inserts a single log entry.
func (r *LogEntryRepo) Create(ctx context.Context, e *model.LogEntry) error {
	col, err := r.db.Collection(ctx, logEntriesCollection)
	if err != nil {
		return fmt.Errorf("log_entries collection: %w", err)
	}
	meta, err := col.CreateDocument(ctx, e)
	if err != nil {
		return fmt.Errorf("log_entry create: %w", err)
	}
	e.Key = meta.Key
	return nil
}

// BulkCreate inserts a slice of log entries using the ArangoDB Documents API
// (multi-document create), which is more reliable than a FOR…INSERT AQL with
// a large @docs bind variable.
func (r *LogEntryRepo) BulkCreate(ctx context.Context, entries []*model.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	col, err := r.db.Collection(ctx, logEntriesCollection)
	if err != nil {
		return fmt.Errorf("log_entries collection: %w", err)
	}
	// Insert in batches of 200 to keep individual requests small
	const batchSize = 200
	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[i:end]
		docs := make([]any, len(batch))
		for j, e := range batch {
			docs[j] = e
		}
		reader, err := col.CreateDocuments(ctx, docs)
		if err != nil {
			return fmt.Errorf("log_entry bulk insert (batch %d): %w", i/batchSize, err)
		}
		// Drain the reader — required for the HTTP response to be fully consumed
		// and the documents to be committed.
		for {
			_, readErr := reader.Read()
			if readErr != nil {
				break // io.EOF signals normal completion
			}
		}
	}
	return nil
}

// ListOptions for log queries.
type LogListOptions struct {
	TenantID  string
	Dataset   string
	AgentID   string
	Hostname  string
	Kind      *uint8
	Page      int
	PageSize  int
	SortBy    string
	SortDesc  bool
}

// List returns a paginated slice of log entries matching the given filters.
func (r *LogEntryRepo) List(ctx context.Context, opts LogListOptions) ([]model.LogEntry, model.PageMeta, error) {
	filters := []string{"doc.tenant_id == @tid"}
	bindVars := map[string]any{"tid": opts.TenantID}

	if opts.Dataset != "" {
		filters = append(filters, "doc.dataset == @dataset")
		bindVars["dataset"] = opts.Dataset
	}
	if opts.AgentID != "" {
		filters = append(filters, "doc.agent_id == @agent_id")
		bindVars["agent_id"] = opts.AgentID
	}
	if opts.Hostname != "" {
		filters = append(filters, "doc.hostname == @hostname")
		bindVars["hostname"] = opts.Hostname
	}
	if opts.Kind != nil {
		filters = append(filters, "doc.kind == @kind")
		bindVars["kind"] = *opts.Kind
	}

	sortBy := opts.SortBy
	if sortBy == "" {
		sortBy = "event_timestamp"
	}
	var entries []model.LogEntry
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: logEntriesCollection,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     sortBy,
		SortDesc:   opts.SortDesc,
		Page:       opts.Page,
		PageSize:   opts.PageSize,
	}, &entries)
	if err != nil {
		return nil, model.PageMeta{}, err
	}
	return entries, meta, nil
}

// CountByDataset returns per-dataset event counts for the given tenant.
// Useful for the dashboard log-volume widget.
func (r *LogEntryRepo) CountByDataset(ctx context.Context, tenantID string) (map[string]int64, error) {
	aql := `
		FOR doc IN log_entries
		  FILTER doc.tenant_id == @tid
		  COLLECT dataset = doc.dataset WITH COUNT INTO cnt
		  RETURN { dataset, cnt }
	`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return nil, fmt.Errorf("log_entry count by dataset: %w", err)
	}
	defer cursor.Close()

	result := map[string]int64{}
	for cursor.HasMore() {
		var row struct {
			Dataset string `json:"dataset"`
			Cnt     int64  `json:"cnt"`
		}
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		result[row.Dataset] = row.Cnt
	}
	return result, nil
}
