package threat

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type RuleHandler struct {
	svc *RuleService
}

func NewRuleHandler(svc *RuleService) *RuleHandler {
	return &RuleHandler{svc: svc}
}

func (h *RuleHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), repository.DetectionRuleListFilter{
		TenantID: tenantID,
		RuleType: c.Query("rule_type"),
		Status:   c.Query("status"),
		Keyword:  c.Query("keyword"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *RuleHandler) Get(c *gin.Context) {
	rule, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "detection_rule")
		return
	}
	response.OK(c, rule)
}

func (h *RuleHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var rule model.DetectionRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	rule.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &rule, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, rule)
}

func (h *RuleHandler) Update(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Update(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *RuleHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *RuleHandler) TransitionStatus(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.TransitionStatus(c.Request.Context(), key, body.Status, operatorID); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, gin.H{"_key": key, "status": body.Status})
}

func (h *RuleHandler) TestReplay(c *gin.Context) {
	key := c.Param("id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	result, err := h.svc.TestReplay(c.Request.Context(), key, hours)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *RuleHandler) MitreCoverage(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	coverage, err := h.svc.MitreCoverage(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	type tacticCount struct {
		Tactic    string `json:"tactic"`
		RuleCount int    `json:"rule_count"`
	}
	tactics := make([]tacticCount, 0, len(coverage))
	for tactic, cnt := range coverage {
		tactics = append(tactics, tacticCount{Tactic: tactic, RuleCount: cnt})
	}
	response.OK(c, gin.H{"tactics": tactics})
}

func (h *RuleHandler) Test(c *gin.Context) {
	key := c.Param("id")
	var body struct {
		SampleEvent map[string]any `json:"sample_event" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	result, err := h.svc.TestSampleEvent(c.Request.Context(), key, body.SampleEvent)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, result)
}

// HitStats returns hit statistics for a detection rule from the DB.
// GET /api/detection_rules/:id/hit_stats
// The rule's hit_count field holds the cumulative total; last_hit_at
// records when it last fired.  Per-window counts are derived from the
// alerts collection filtered by rule_id.
func (h *RuleHandler) HitStats(c *gin.Context) {
	key := c.Param("id")
	rule, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, "detection_rule")
		return
	}
	c.JSON(200, gin.H{
		"rule_key":            key,
		"total_hits":          rule.HitCount,
		"last_hit_at":         rule.LastHitAt,
	})
}

// BulkToggle enables or disables multiple detection rules.
// POST /api/detection_rules/bulk
// Body: { "action": "enable|disable", "keys": ["key1", "key2", ...] }
func (h *RuleHandler) BulkToggle(c *gin.Context) {
	var body struct {
		Action string   `json:"action" binding:"required"`
		Keys   []string `json:"keys"`
		IDs    []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	if len(keys) == 0 {
		response.BadRequest(c, "keys or ids required")
		return
	}
	var statusVal string
	switch body.Action {
	case "enable":
		statusVal = "active"
	case "disable":
		statusVal = "inactive"
	default:
		response.BadRequest(c, "unknown action: "+body.Action)
		return
	}
	count := 0
	for _, k := range keys {
		if err := h.svc.Update(c.Request.Context(), k, map[string]any{"status": statusVal}); err == nil {
			count++
		}
	}
	c.JSON(200, gin.H{"updated": count, "action": body.Action})
}
