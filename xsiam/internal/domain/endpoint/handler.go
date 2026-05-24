package endpoint

import (
	"strconv"
	"time"
	"xsiam/internal/middleware"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

// Handler handles all /api/endpoint/* endpoints.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ─── GET /api/endpoint/stats ──────────────────────────────────────────────────

func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.Stats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}

// ─── GET /api/endpoint/isolated ───────────────────────────────────────────────

func (h *Handler) ListIsolated(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListIsolated(c.Request.Context(), tenantID, page, pageSize, c.Query("status"))
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// ─── POST /api/endpoint/isolated ─────────────────────────────────────────────

func (h *Handler) IsolateEndpoint(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		DeviceKey string `json:"device_key" binding:"required"`
		Reason    string `json:"reason"     binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	iso, err := h.svc.IsolateEndpoint(c.Request.Context(), tenantID, body.DeviceKey, body.Reason, operatorID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, iso)
}

// ─── PUT /api/endpoint/isolated/:id/release ───────────────────────────────────

func (h *Handler) ReleaseIsolation(c *gin.Context) {
	operatorID := c.GetString(middleware.CtxUserID)
	key := c.Param("id")
	if err := h.svc.ReleaseIsolation(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "status": "released", "released_at": time.Now()})
}
