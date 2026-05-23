package asset

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colVulns = "vulnerabilities"

// VulnRepo is the ArangoDB-backed vulnerability repository.
type VulnRepo struct {
	db arangodb.Database
}

func NewVulnRepo(db arangodb.Database) *VulnRepo {
	return &VulnRepo{db: db}
}

func (r *VulnRepo) List(ctx context.Context, f repository.VulnerabilityListFilter) ([]model.Vulnerability, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Severity != "" {
		filters = append(filters, "doc.severity == @severity")
		bindVars["severity"] = f.Severity
	}
	if f.FixStatus != "" {
		filters = append(filters, "doc.fix_status == @fixStatus")
		bindVars["fixStatus"] = f.FixStatus
	}
	if f.Keyword != "" {
		filters = append(filters, "(CONTAINS(LOWER(doc.title), LOWER(@kw)) OR CONTAINS(LOWER(doc.cve_id), LOWER(@kw)))")
		bindVars["kw"] = f.Keyword
	}

	var data []model.Vulnerability
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colVulns,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *VulnRepo) GetByID(ctx context.Context, key string) (*model.Vulnerability, error) {
	col, _ := r.db.Collection(ctx, colVulns)
	var v model.Vulnerability
	if _, err := col.ReadDocument(ctx, key, &v); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("vulnerability %s not found", key)
		}
		return nil, err
	}
	return &v, nil
}

func (r *VulnRepo) Create(ctx context.Context, v *model.Vulnerability) error {
	now := time.Now()
	v.CreatedAt = now
	v.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colVulns)
	meta, err := col.CreateDocument(ctx, v)
	if err != nil {
		return err
	}
	v.Key = meta.Key
	return nil
}

func (r *VulnRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colVulns)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *VulnRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colVulns)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

func (r *VulnRepo) Stats(ctx context.Context, tenantID string) (map[string]any, error) {
	query := `
		FOR doc IN vulnerabilities
		FILTER doc.tenant_id == @tenantID
		COLLECT severity = doc.severity, fixStatus = doc.fix_status WITH COUNT INTO cnt
		RETURN {severity, fix_status: fixStatus, count: cnt}
	`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var rows []map[string]any
	for cursor.HasMore() {
		var row map[string]any
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return map[string]any{"breakdown": rows}, nil
}
