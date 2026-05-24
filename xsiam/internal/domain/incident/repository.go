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

// slaRow is used to unmarshal the aggregated AQL SLA result.
type slaRow struct {
	Total      int     `json:"total"`
	P1Breached int     `json:"p1_breached"`
	P2Breached int     `json:"p2_breached"`
	P1AtRisk   int     `json:"p1_at_risk"`
	P2AtRisk   int     `json:"p2_at_risk"`
	Compliant  int     `json:"compliant"`
}

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
	if f.Priority != "" {
		filters = append(filters, "doc.priority == @priority")
		bindVars["priority"] = f.Priority
	}
	if f.AssigneeID != "" {
		filters = append(filters, "doc.assignee_id == @assigneeId")
		bindVars["assigneeId"] = f.AssigneeID
	}
	if f.Keyword != "" {
		filters = append(filters, "(CONTAINS(LOWER(doc.name), LOWER(@kw)) OR CONTAINS(LOWER(doc.title), LOWER(@kw)) OR CONTAINS(LOWER(doc.description), LOWER(@kw)))")
		bindVars["kw"] = f.Keyword
	}
	if f.MitreTactic != "" {
		filters = append(filters, "(@mitreTactic IN doc.mitre_tactics OR doc.mitre_tactic == @mitreTactic)")
		bindVars["mitreTactic"] = f.MitreTactic
	}
	if f.AssignedTo != "" {
		filters = append(filters, "doc.assigned_to == @assignedTo")
		bindVars["assignedTo"] = f.AssignedTo
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

// GetSLAStats computes SLA compliance for all open incidents of a tenant.
// SLA hours by priority/severity: P1/critical=4h, P2/high=8h, P3/medium=24h, P4/default=72h.
// Breached = open incident where deadline < now.
// At risk  = open incident where time until deadline < 2h AND NOT breached.
func (r *Repo) GetSLAStats(ctx context.Context, tenantID string) (*SLAStats, error) {
	aql := `
FOR doc IN incidents
  FILTER doc.tenant_id == @tenantID
  LET sla_hours = (doc.priority == "P1" OR doc.severity == "critical") ? 4 :
                  (doc.priority == "P2" OR doc.severity == "high") ? 8 :
                  (doc.priority == "P3" OR doc.severity == "medium") ? 24 : 72
  LET deadline = DATE_ADD(doc.created_at, sla_hours, "hours")
  LET breached = (doc.status NOT IN ["resolved","auto_closed","false_positive"] AND deadline < DATE_NOW())
  LET at_risk = (!breached AND doc.status NOT IN ["resolved","auto_closed","false_positive"] AND DATE_DIFF(DATE_NOW(), deadline, "hours") < 2)
  COLLECT INTO rows
  RETURN {
    total: LENGTH(rows),
    p1_breached: COUNT(rows[* FILTER CURRENT.sla_hours == 4 AND CURRENT.breached]),
    p2_breached: COUNT(rows[* FILTER CURRENT.sla_hours == 8 AND CURRENT.breached]),
    p1_at_risk: COUNT(rows[* FILTER CURRENT.sla_hours == 4 AND CURRENT.at_risk]),
    p2_at_risk: COUNT(rows[* FILTER CURRENT.sla_hours == 8 AND CURRENT.at_risk]),
    compliant: COUNT(rows[* FILTER !CURRENT.breached])
  }
`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	// The COLLECT INTO ... RETURN query returns exactly one row (or zero if no docs).
	var row slaRow
	if cursor.HasMore() {
		if _, err := cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
	}

	var complianceRate float64
	if row.Total > 0 {
		complianceRate = float64(row.Compliant) / float64(row.Total)
	}

	return &SLAStats{
		Total:          row.Total,
		P1Breached:     row.P1Breached,
		P2Breached:     row.P2Breached,
		P1AtRisk:       row.P1AtRisk,
		P2AtRisk:       row.P2AtRisk,
		ComplianceRate: complianceRate,
	}, nil
}
