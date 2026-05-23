package device

import (
	"strconv"
	"strings"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc      *Service
	liveness *LivenessRegistry
}

func NewHandler(svc *Service, liveness *LivenessRegistry) *Handler {
	return &Handler{svc: svc, liveness: liveness}
}

func (h *Handler) ListAgents(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListAgents(c.Request.Context(), repository.DeviceListFilter{
		TenantID:    tenantID,
		AgentStatus: c.Query("status"),
		Keyword:     c.Query("keyword"),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
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

// Liveness returns online/offline status for a list of agent_ids.
// POST /api/devices/liveness  body: {"agent_ids":["agent-00001","agent-00002"]}
// GET  /api/devices/liveness?ids=agent-00001,agent-00002
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
		// GET ?ids=a,b,c
		raw := c.Query("ids")
		if raw == "" {
			response.BadRequest(c, "ids query param required")
			return
		}
		agentIDs = strings.Split(raw, ",")
	}

	statusMap := h.liveness.QueryBatch(agentIDs)
	response.OK(c, gin.H{"online": statusMap})
}

// Heartbeat receives a heartbeat from fluent-bit's HTTP output plugin.
// POST /api/devices/:id/heartbeat
// The :id is the device _key; body may contain agent_id for cross-reference.
func (h *Handler) Heartbeat(c *gin.Context) {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	_ = c.ShouldBindJSON(&body)

	// Prefer explicit agent_id from body; fallback to device key lookup
	agentID := body.AgentID
	if agentID == "" {
		// Resolve device key → agent_id
		key := c.Param("id")
		dev, err := h.svc.GetAgent(c.Request.Context(), key)
		if err == nil && dev.AgentID != "" {
			agentID = dev.AgentID
		} else {
			agentID = key // last resort: use the key directly
		}
	}

	h.liveness.RecordHeartbeat(agentID)
	c.Status(204)
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
