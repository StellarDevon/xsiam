package incident

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colIncidents = "incidents"

// Repo is the ArangoDB-backed incident repository.
type Repo struct {
	db arangodb.Database
}

func NewRepo(db arangodb.Database) *Repo {
	return &Repo{db: db}
}

func (r *Repo) List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Severity != "" {
		filters = append(filters, "doc.severity == @severity")
		bindVars["severity"] = f.Severity
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}
	if f.AssigneeID != "" {
		filters = append(filters, "doc.assignee_id == @assigneeId")
		bindVars["assigneeId"] = f.AssigneeID
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	sortBy := "last_activity"
	if f.SortBy != "" {
		sortBy = f.SortBy
	}

	var data []model.Incident
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colIncidents,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     sortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *Repo) GetByID(ctx context.Context, key string) (*model.Incident, error) {
	col, _ := r.db.Collection(ctx, colIncidents)
	var inc model.Incident
	if _, err := col.ReadDocument(ctx, key, &inc); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("incident %s not found", key)
		}
		return nil, err
	}
	return &inc, nil
}

func (r *Repo) Create(ctx context.Context, inc *model.Incident) error {
	now := time.Now()
	inc.CreatedAt = now
	inc.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colIncidents)
	meta, err := col.CreateDocument(ctx, inc)
	if err != nil {
		return err
	}
	inc.Key = meta.Key
	return nil
}

func (r *Repo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colIncidents)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *Repo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colIncidents)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

func (r *Repo) ListAlertKeys(ctx context.Context, incidentKey string) ([]string, error) {
	aql := `FOR doc IN alerts FILTER doc.incident_id == @key RETURN doc._key`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{BindVars: map[string]any{"key": incidentKey}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var keys []string
	for cursor.HasMore() {
		var k string
		if _, err := cursor.ReadDocument(ctx, &k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (r *Repo) Merge(ctx context.Context, primaryKey string, secondaryKeys []string) error {
	aql := `FOR k IN @keys
		FOR doc IN alerts FILTER doc.incident_id == k
		UPDATE doc WITH {incident_id: @primary} IN alerts`
	_, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"keys": secondaryKeys, "primary": primaryKey},
	})
	if err != nil {
		return err
	}
	for _, k := range secondaryKeys {
		if err := r.Delete(ctx, k); err != nil {
			return err
		}
	}
	return nil
}
