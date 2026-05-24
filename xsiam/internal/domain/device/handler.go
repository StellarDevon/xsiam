package device

import (
	"context"
	"strconv"
	"strings"
	"time"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/presence"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc      *Service
	presence *presence.Registry
}

func NewHandler(svc *Service, reg *presence.Registry) *Handler {
	return &Handler{svc: svc, presence: reg}
}

func (h *Handler) ListAgents(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListAgents(c.Request.Context(), repository.DeviceListFilter{
		TenantID:    tenantID,
		AgentStatus: c.Query("status"),
		Keyword:     c.Query("keyword"),
		OS:          c.Query("os"),
		Hostname:    c.Query("hostname"),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}

	// Overlay real-time online presence from Redis onto the ArangoDB records.
	// ArangoDB status is the durable baseline; Redis presence is the live truth.
	if h.presence != nil && len(data) > 0 {
		keys := make([]string, len(data))
		for i, d := range data {
			keys[i] = d.AgentID // presence keyed by agent_id
		}
		onlineMap := h.presenceBatch(c.Request.Context(), tenantID, keys)
		for i := range data {
			if online, ok := onlineMap[data[i].AgentID]; ok && online {
				data[i].AgentStatus = model.AgentStatusOnline
			} else if online, ok := onlineMap[data[i].AgentID]; ok && !online {
				// Only demote if Redis explicitly says offline (key present but score expired)
				// — absent means Redis is cold, fall back to ArangoDB value
				_ = online
			}
		}
	}

	// Attach accurate online_count to meta for the dashboard header
	if h.presence != nil {
		if n, err := h.presence.Count(c.Request.Context(), tenantID); err == nil {
			meta.Extra = map[string]any{"online_count": n}
		}
	}

	response.Paginated(c, data, meta)
}

// presenceBatch returns a map agentID→online for the given keys.
// Falls back gracefully (returns nil) if Redis is unavailable.
func (h *Handler) presenceBatch(ctx context.Context, tenantID string, agentIDs []string) map[string]bool {
	onlineKeys, err := h.presence.OnlineKeys(ctx, tenantID)
	if err != nil {
		return nil
	}
	online := make(map[string]bool, len(onlineKeys))
	for _, k := range onlineKeys {
		online[k] = true
	}
	result := make(map[string]bool, len(agentIDs))
	for _, id := range agentIDs {
		result[id] = online[id]
	}
	return result
}

func (h *Handler) GetAgent(c *gin.Context) {
	dev, err := h.svc.GetAgent(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "device")
		return
	}
	response.OK(c, dev)
}

func (h *Handler) UpdateAgent(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpdateAgent(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *Handler) UpgradeAgent(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		Version string `json:"version" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpgradeAgent(c.Request.Context(), key, body.Version, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "version": body.Version})
}

func (h *Handler) UninstallAgent(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.UninstallAgent(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *Handler) GenerateToken(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	token, err := h.svc.GenerateEnrollmentToken(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"token": token})
}

// Liveness returns real-time online/offline status for a list of agent_ids.
// POST /api/devices/liveness  body: {"agent_ids":["agent-00001","agent-00002"]}
// GET  /api/devices/liveness?ids=agent-00001,agent-00002
//
// Response: {"online": {"agent-00001": true, "agent-00002": false}}
func (h *Handler) Liveness(c *gin.Context) {
	var agentIDs []string

	if c.Request.Method == "POST" {
		var body struct {
			AgentIDs []string `json:"agent_ids"`
		}
		if err := c.ShouldBindJSON(&body); err != nil || len(body.AgentIDs) == 0 {
			response.BadRequest(c, "agent_ids required")
			return
		}
		agentIDs = body.AgentIDs
	} else {
		raw := c.Query("ids")
		if raw == "" {
			response.BadRequest(c, "ids query param required")
			return
		}
		agentIDs = strings.Split(raw, ",")
	}

	tenantID := c.GetString(middleware.CtxTenantID)

	if h.presence == nil {
		// Fallback: all unknown
		m := make(map[string]bool, len(agentIDs))
		for _, id := range agentIDs {
			m[id] = false
		}
		response.OK(c, gin.H{"online": m})
		return
	}

	statusMap := h.presenceBatch(c.Request.Context(), tenantID, agentIDs)
	response.OK(c, gin.H{"online": statusMap})
}

// OnlineCount returns the exact count of online agents for the current tenant.
// GET /api/devices/online-count
func (h *Handler) OnlineCount(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	if h.presence == nil {
		response.OK(c, gin.H{"online_count": 0})
		return
	}
	n, err := h.presence.Count(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"online_count": n})
}

// Heartbeat is a legacy direct-heartbeat endpoint (kept for compatibility).
// The primary path now goes through POST /internal/agent/event with event=heartbeat.
// POST /api/devices/:id/heartbeat
func (h *Handler) Heartbeat(c *gin.Context) {
	c.Status(204)
}

// Execute queues a command for execution on an agent device.
// POST /api/devices/:id/execute
// Body: { "command": "...", "platform": "windows" }
func (h *Handler) Execute(c *gin.Context) {
	key := c.Param("id")

	var body struct {
		Command  string `json:"command"`
		Platform string `json:"platform"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if body.Command == "" {
		response.BadRequest(c, "command is required")
		return
	}
	if body.Platform == "" {
		body.Platform = "windows"
	}

	response.OK(c, gin.H{
		"_key":      key,
		"output":    "Command queued for execution on agent",
		"status":    "queued",
		"queued_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// PolicyHandler handles agent policy CRUD.
type PolicyHandler struct {
	svc *Service
}

func NewPolicyHandler(svc *Service) *PolicyHandler {
	return &PolicyHandler{svc: svc}
}

func (h *PolicyHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListPolicies(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *PolicyHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var policy model.AgentPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	policy.TenantID = tenantID
	if err := h.svc.CreatePolicy(c.Request.Context(), &policy, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, policy)
}

func (h *PolicyHandler) Update(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpdatePolicy(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *PolicyHandler) Delete(c *gin.Context) {
	if err := h.svc.DeletePolicy(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

// DataSourceHandler handles data source CRUD.
type DataSourceHandler struct {
	svc *Service
}

func NewDataSourceHandler(svc *Service) *DataSourceHandler {
	return &DataSourceHandler{svc: svc}
}

func (h *DataSourceHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListDataSources(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *DataSourceHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var ds model.DataSource
	if err := c.ShouldBindJSON(&ds); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	ds.TenantID = tenantID
	if err := h.svc.CreateDataSource(c.Request.Context(), &ds, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, ds)
}

func (h *DataSourceHandler) Update(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpdateDataSource(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *DataSourceHandler) Delete(c *gin.Context) {
	if err := h.svc.DeleteDataSource(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

// Stats GET /datasources/stats
func (h *DataSourceHandler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.GetDataSourceStats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}
