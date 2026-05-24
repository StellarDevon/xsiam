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
	if f.OS != "" {
		filters = append(filters, "LOWER(doc.os) LIKE LOWER(CONCAT('%', @os, '%'))")
		bindVars["os"] = f.OS
	}
	if f.Hostname != "" {
		filters = append(filters, "LOWER(doc.hostname) LIKE LOWER(CONCAT('%', @hostname, '%'))")
		bindVars["hostname"] = f.Hostname
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

// BulkOfflineByAgentKeys sets status=offline for all devices whose agent_id is in agentKeys
// and belong to tenantID. Implements presence.DeviceStatusUpdater.
func (r *Repo) BulkOfflineByAgentKeys(ctx context.Context, tenantID string, agentKeys []string) error {
	if len(agentKeys) == 0 {
		return nil
	}
	now := time.Now()
	aql := `
FOR doc IN devices
  FILTER doc.tenant_id == @tenantID
  FILTER doc.agent_id IN @agentKeys
  FILTER doc.agent_status == 'online'
  UPDATE doc WITH {
    agent_status: 'offline',
    updated_at:   @now
  } IN devices
`
	_, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{
			"tenantID":  tenantID,
			"agentKeys": agentKeys,
			"now":       now,
		},
	})
	return err
}

// TenantForAgentKey returns the tenant_id for the device whose agent_id matches key.
// Returns ("", nil) when not found. Implements presence.DeviceStatusUpdater.
func (r *Repo) TenantForAgentKey(ctx context.Context, agentKey string) (string, error) {
	aql := `FOR doc IN devices FILTER doc.agent_id == @key LIMIT 1 RETURN doc.tenant_id`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"key": agentKey},
	})
	if err != nil {
		return "", err
	}
	defer cursor.Close()
	var tenantID string
	if _, err := cursor.ReadDocument(ctx, &tenantID); err != nil {
		return "", nil // not found
	}
	return tenantID, nil
}
