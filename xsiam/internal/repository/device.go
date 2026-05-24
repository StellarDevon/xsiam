package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colDevices = "devices"

type DeviceRepo struct {
	db arangodb.Database
}

func NewDeviceRepo(db arangodb.Database) *DeviceRepo {
	return &DeviceRepo{db: db}
}

type DeviceListFilter struct {
	TenantID    string
	AgentStatus string
	Keyword     string
	OS          string
	Hostname    string
	Page        int
	PageSize    int
	SortBy      string
	SortDesc    bool
}

func (r *DeviceRepo) List(ctx context.Context, f DeviceListFilter) ([]model.Device, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

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
	meta, err := FindPaged(ctx, r.db, ListOptions{
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

func (r *DeviceRepo) GetByID(ctx context.Context, key string) (*model.Device, error) {
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

func (r *DeviceRepo) Create(ctx context.Context, dev *model.Device) error {
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

func (r *DeviceRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colDevices)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
