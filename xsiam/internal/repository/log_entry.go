package repository

import (
	"context"
	"fmt"
	"log"
	"sync"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const logEntriesCollection = "log_entries"

// LogEntryRepo handles reads/writes for structured log entries stored in
// ArangoDB.  Each ETL rule may route entries to a user-defined collection;
// the repo ensures those collections and their TTL indexes exist on demand.
type LogEntryRepo struct {
	db         arangodb.Database
	mu         sync.RWMutex
	ensuredCols map[string]bool // set of collection names already ensured
}

func NewLogEntryRepo(db arangodb.Database) *LogEntryRepo {
	return &LogEntryRepo{
		db:          db,
		ensuredCols: map[string]bool{logEntriesCollection: true}, // pre-ensured at startup
	}
}

// ensureETLCollection creates the named collection (if it doesn't exist) and
// sets a TTL index on event_timestamp when ttlDays > 0.  Results are cached
// so subsequent calls for the same collection are O(1) map lookups.
func (r *LogEntryRepo) ensureETLCollection(ctx context.Context, colName string, ttlDays int) error {
	r.mu.RLock()
	already := r.ensuredCols[colName]
	r.mu.RUnlock()
	if already {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Double-check after acquiring write lock.
	if r.ensuredCols[colName] {
		return nil
	}

	exists, err := r.db.CollectionExists(ctx, colName)
	if err != nil {
		return fmt.Errorf("check collection %s: %w", colName, err)
	}
	if !exists {
		if _, err = r.db.CreateCollection(ctx, colName, nil); err != nil {
			return fmt.Errorf("create collection %s: %w", colName, err)
		}
		log.Printf("[repo] created ETL collection %q", colName)
	}

	if ttlDays > 0 {
		col, err := r.db.Collection(ctx, colName)
		if err != nil {
			return fmt.Errorf("open collection %s: %w", colName, err)
		}
		expireSecs := ttlDays * 86400
		if _, _, err = col.EnsureTTLIndex(ctx, []string{"event_timestamp"}, expireSecs, nil); err != nil {
			log.Printf("[repo] ensureTTLIndex %s: %v", colName, err)
			// Non-fatal — collection is still usable without the index.
		}
	}

	r.ensuredCols[colName] = true
	return nil
}

// Create inserts a single log entry into the default log_entries collection.
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

// BulkCreate inserts a slice of log entries into the named ArangoDB collection.
//
//   - collection : user-defined ETL sink collection name (e.g. "proc_events").
//     Pass logEntriesCollection ("log_entries") to write to the default collection.
//   - ttlDays    : TTL for the collection in days (0 = no TTL).  Only applied
//     when the collection is first created; subsequent calls for the same
//     collection use the cached handle.
//
// The collection is created on-demand with the requested TTL index.
// Insert batches are capped at 200 documents to keep individual HTTP requests small.
func (r *LogEntryRepo) BulkCreate(ctx context.Context, collection string, ttlDays int, entries []*model.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	if collection == "" {
		collection = logEntriesCollection
	}
	if err := r.ensureETLCollection(ctx, collection, ttlDays); err != nil {
		return err
	}
	col, err := r.db.Collection(ctx, collection)
	if err != nil {
		return fmt.Errorf("open collection %s: %w", collection, err)
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
			return fmt.Errorf("bulk insert %s (batch %d): %w", collection, i/batchSize, err)
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
