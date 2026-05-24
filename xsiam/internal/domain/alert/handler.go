package alert

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
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
		Host:       c.Query("host"),
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
		Action     string         `json:"action" binding:"required"`
		Keys       []string       `json:"keys"`
		IDs        []string       `json:"ids"`
		Patch      map[string]any `json:"patch"`
		Status     string         `json:"status"`
		AssignedTo string         `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	// Accept either "keys" or "ids" as the list of document keys.
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	if len(keys) == 0 {
		response.BadRequest(c, "ids or keys is required and must not be empty")
		return
	}
	var patch map[string]any
	switch body.Action {
	case "close":
		patch = map[string]any{"status": string(model.AlertStatusAutoClosed)}
	case "status":
		if body.Status == "" {
			response.BadRequest(c, "status field required for status action")
			return
		}
		patch = map[string]any{"status": body.Status}
	case "assign":
		if body.AssignedTo == "" {
			response.BadRequest(c, "assigned_to field required for assign action")
			return
		}
		patch = map[string]any{"assignee_id": body.AssignedTo}
	case "resolve":
		patch = map[string]any{"status": string(model.AlertStatusResolved)}
	case "update":
		if body.Patch == nil {
			response.BadRequest(c, "patch required for update action")
			return
		}
		patch = body.Patch
	default:
		response.BadRequest(c, "unknown action: "+body.Action)
		return
	}
	if err := h.svc.Bulk(c.Request.Context(), keys, body.Action, patch, operatorID); err != nil {
		response.Err(c, http.StatusMultiStatus, "PARTIAL_ERROR", err.Error())
		return
	}
	response.OK(c, gin.H{"updated": len(keys)})
}

func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.GetStats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}

// Summary generates an AI summary for a specific alert.
// GET /api/alerts/:id/summary
func (h *Handler) Summary(c *gin.Context) {
	key := c.Param("id")
	a, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "alert")
		return
	}
	summary := fmt.Sprintf(
		"Alert '%s' (severity: %s, status: %s) was triggered at %s. Source: %s. Host: %s.",
		a.Name, a.Severity, a.Status, a.TriggeredAt.Format(time.RFC3339), a.SourceType, a.Host,
	)
	c.JSON(http.StatusOK, gin.H{
		"summary":     summary,
		"alert_key":   key,
		"ai_enhanced": false,
	})
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
