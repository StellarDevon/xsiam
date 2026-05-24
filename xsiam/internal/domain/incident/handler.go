package incident

import (
	"encoding/csv"
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
	f := repository.IncidentListFilter{
		TenantID:    tenantID,
		Severity:    c.Query("severity"),
		Status:      c.Query("status"),
		Priority:    c.Query("priority"),
		AssigneeID:  c.Query("assignee_id"),
		AssignedTo:  firstOf(c.Query("assigned_to"), c.Query("assignee_id")),
		Unassigned:  c.Query("unassigned") == "true",
		Keyword:     firstOf(c.Query("q"), c.Query("keyword")),
		MitreTactic: c.Query("mitre_tactic"),
		HoursAgo:    hoursAgo,
		Page:        page,
		PageSize:    pageSize,
		SortBy:      c.Query("sort_by"),
		SortDesc:    c.Query("sort_desc") == "true",
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
	inc, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "incident")
		return
	}
	response.OK(c, inc)
}

func (h *Handler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var req CreateIncidentReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if req.Title == "" && req.Name == "" {
		response.BadRequest(c, "title or name is required")
		return
	}
	req.TenantID = tenantID
	inc, err := h.svc.Create(c.Request.Context(), req, operatorID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, inc)
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

func (h *Handler) Delete(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.Delete(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *Handler) ListAlerts(c *gin.Context) {
	key := c.Param("id")
	alerts, err := h.svc.ListAlerts(c.Request.Context(), key)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	if alerts == nil {
		alerts = []model.Alert{}
	}
	response.OK(c, gin.H{"items": alerts})
}

func (h *Handler) AddNote(c *gin.Context) {
	key := c.Param("id")
	authorID := c.GetString(middleware.CtxUserID)
	var body struct {
		Content    string `json:"content" binding:"required"`
		AuthorName string `json:"author_name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.AddNote(c.Request.Context(), key, body.Content, authorID, body.AuthorName); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *Handler) GetTimeline(c *gin.Context) {
	key := c.Param("id")
	inc, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "incident")
		return
	}
	type TimelineEvent struct {
		EventType   string `json:"event_type"`
		Description string `json:"description"`
		Actor       string `json:"actor,omitempty"`
		CreatedAt   string `json:"created_at"`
	}
	var events []TimelineEvent
	events = append(events, TimelineEvent{
		EventType:   "created",
		Description: "Incident created — " + inc.Name,
		CreatedAt:   inc.FirstSeen.Format("2006-01-02T15:04:05Z"),
	})
	if inc.AssignedTo != "" {
		events = append(events, TimelineEvent{
			EventType:   "assigned",
			Description: "Assigned to " + inc.AssignedTo,
			CreatedAt:   inc.LastActivity.Format("2006-01-02T15:04:05Z"),
		})
	}
	if string(inc.Status) != "new" {
		events = append(events, TimelineEvent{
			EventType:   "status",
			Description: "Status changed to " + string(inc.Status),
			CreatedAt:   inc.LastActivity.Format("2006-01-02T15:04:05Z"),
		})
	}
	for _, n := range inc.Notes {
		preview := n.Content
		if len(preview) > 80 {
			preview = preview[:80] + "…"
		}
		events = append(events, TimelineEvent{
			EventType:   "note",
			Description: "Note: " + preview,
			Actor:       n.AuthorName,
			CreatedAt:   n.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}
	response.OK(c, gin.H{"items": events})
}

func (h *Handler) Merge(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		SecondaryKeys []string `json:"secondary_keys" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Merge(c.Request.Context(), key, body.SecondaryKeys, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
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
	if err := h.svc.Bulk(c.Request.Context(), body.Keys, body.Action, body.Patch, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"updated": len(body.Keys)})
}

func (h *Handler) SLAStats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.GetSLAStats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}

// Summary generates an AI summary for an incident.
// GET /api/incidents/:id/summary
func (h *Handler) Summary(c *gin.Context) {
	key := c.Param("id")
	inc, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "incident")
		return
	}
	summary := fmt.Sprintf(
		"Incident '%s' (severity: %s, status: %s) was created at %s with SmartScore %.1f. Total alerts: %d.",
		inc.Title, inc.Severity, inc.Status, inc.CreatedAt.Format(time.RFC3339), inc.SmartScore, inc.AlertCount,
	)
	c.JSON(http.StatusOK, gin.H{
		"summary":      summary,
		"incident_key": key,
		"ai_enhanced":  false,
	})
}

// Export returns all incidents for this tenant as CSV.
// GET /api/incidents/export
func (h *Handler) Export(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	incs, _, err := h.svc.List(c.Request.Context(), repository.IncidentListFilter{
		TenantID: tenantID, PageSize: 10000, Page: 1,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	c.Header("Content-Disposition", `attachment; filename="incidents.csv"`)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"_key", "title", "severity", "status", "smart_score", "alert_count", "created_at"})
	for _, inc := range incs {
		_ = w.Write([]string{
			inc.Key,
			inc.Title,
			string(inc.Severity),
			string(inc.Status),
			fmt.Sprintf("%.1f", inc.SmartScore),
			fmt.Sprintf("%d", inc.AlertCount),
			inc.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
}

// SLARecalc recomputes SLA status for a specific incident.
// POST /api/incidents/:id/sla_recalc
func (h *Handler) SLARecalc(c *gin.Context) {
	key := c.Param("id")
	inc, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "incident")
		return
	}
	slaLimits := map[string]float64{
		"critical": 4, "high": 8, "medium": 24, "low": 72,
	}
	limit := slaLimits[string(inc.Severity)]
	if limit == 0 {
		limit = 72
	}
	elapsed := time.Since(inc.CreatedAt).Hours()
	remaining := limit - elapsed
	breached := elapsed > limit
	pctUsed := (elapsed / limit) * 100.0
	if pctUsed > 100 {
		pctUsed = 100
	}
	response.OK(c, gin.H{
		"incident_key":    key,
		"breached":        breached,
		"elapsed_hours":   elapsed,
		"limit_hours":     limit,
		"remaining_hours": remaining,
		"pct_used":        pctUsed,
	})
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
