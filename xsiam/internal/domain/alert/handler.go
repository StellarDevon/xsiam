package alert

import (
	"net/http"
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	hoursAgo, _ := strconv.Atoi(c.Query("hours"))

	// Normalise status: SPA may send "new" which maps to "active" in the model.
	status := c.Query("status")
	if status == "new" {
		status = string(model.AlertStatusActive)
	}
	// Accept "source" (SPA alias) or "source_type" (canonical)
	sourceType := firstOf(c.Query("source_type"), c.Query("source"))

	f := repository.AlertListFilter{
		TenantID:   tenantID,
		Severity:   c.Query("severity"),
		Status:     status,
		SourceType: sourceType,
		IncidentID: c.Query("incident_id"),
		AssetID:    c.Query("asset_id"),
		Keyword:    firstOf(c.Query("q"), c.Query("keyword")),
		Unlinked:   c.Query("unlinked") == "true",
		Linked:     c.Query("linked") == "true",
		HoursAgo:   hoursAgo,
		Page:       page,
		PageSize:   pageSize,
		SortBy:     c.Query("sort_by"),
		SortDesc:   c.Query("sort_desc") == "true",
	}
	data, meta, err := h.svc.List(c.Request.Context(), f)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *Handler) Get(c *gin.Context) {
	key := c.Param("id")
	a, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "alert")
		return
	}
	response.OK(c, a)
}

func (h *Handler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var req CreateAlertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	req.TenantID = tenantID
	a, err := h.svc.Create(c.Request.Context(), req, operatorID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, a)
}

func (h *Handler) Update(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Update(c.Request.Context(), key, patch, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *Handler) LinkIncident(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		IncidentID string `json:"incident_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.LinkIncident(c.Request.Context(), key, body.IncidentID, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "incident_id": body.IncidentID})
}

func (h *Handler) Bulk(c *gin.Context) {
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		Action string         `json:"action" binding:"required"`
		Keys   []string       `json:"keys" binding:"required,min=1"`
		Patch  map[string]any `json:"patch"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	patch := body.Patch
	switch body.Action {
	case "close":
		patch = map[string]any{"status": string(model.AlertStatusAutoClosed)}
	case "update":
		if patch == nil {
			response.BadRequest(c, "patch required for update action")
			return
		}
	default:
		response.BadRequest(c, "unknown action: "+body.Action)
		return
	}
	if err := h.svc.Bulk(c.Request.Context(), body.Keys, body.Action, patch, operatorID); err != nil {
		response.Err(c, http.StatusMultiStatus, "PARTIAL_ERROR", err.Error())
		return
	}
	response.OK(c, gin.H{"updated": len(body.Keys)})
}

// firstOf returns the first non-empty string.
func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
