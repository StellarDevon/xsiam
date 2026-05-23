package device

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colDevices = "devices"

// Repo is the ArangoDB-backed device repository.
type Repo struct {
	db arangodb.Database
}

func NewRepo(db arangodb.Database) *Repo {
	return &Repo{db: db}
}

func (r *Repo) List(ctx context.Context, f repository.DeviceListFilter) ([]model.Device, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.AgentStatus != "" {
		filters = append(filters, "doc.agent_status == @agentStatus")
		bindVars["agentStatus"] = f.AgentStatus
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.hostname), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	var data []model.Device
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colDevices,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *Repo) GetByID(ctx context.Context, key string) (*model.Device, error) {
	col, _ := r.db.Collection(ctx, colDevices)
	var dev model.Device
	if _, err := col.ReadDocument(ctx, key, &dev); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("device %s not found", key)
		}
		return nil, err
	}
	return &dev, nil
}

func (r *Repo) Create(ctx context.Context, dev *model.Device) error {
	now := time.Now()
	dev.CreatedAt = now
	dev.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colDevices)
	meta, err := col.CreateDocument(ctx, dev)
	if err != nil {
		return err
	}
	dev.Key = meta.Key
	return nil
}

func (r *Repo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colDevices)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

// FindByAgentID returns the device whose agent_id matches.
// Returns nil, nil when not found.
func (r *Repo) FindByAgentID(ctx context.Context, agentID string) (*model.Device, error) {
	aql := `FOR doc IN devices FILTER doc.agent_id == @agentID LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"agentID": agentID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var dev model.Device
	_, err = cursor.ReadDocument(ctx, &dev)
	if err != nil {
		// no rows — not found
		return nil, nil
	}
	return &dev, nil
}

// UpdateStatusByKey sets agent_status + last_heartbeat atomically.
func (r *Repo) UpdateStatusByKey(ctx context.Context, key string, status model.AgentStatus, now time.Time) error {
	patch := map[string]any{
		model.FieldDeviceAgentStatus: string(status),
		model.FieldDeviceHeartbeat:   now,
		model.FieldUpdatedAt:         now,
	}
	col, _ := r.db.Collection(ctx, colDevices)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
