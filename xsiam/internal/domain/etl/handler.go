package etl

import (
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

// Handler provides the HTTP API for ETL rule management.
//
//	GET    /api/etl/rules          — list rules (paginated, filterable)
//	POST   /api/etl/rules          — create rule
//	GET    /api/etl/rules/:id      — get rule
//	PATCH  /api/etl/rules/:id      — update rule (partial)
//	DELETE /api/etl/rules/:id      — delete rule
//	POST   /api/etl/rules/:id/test — dry-run against a sample event
type Handler struct {
	svc *Service
}

// NewHandler constructs an ETL HTTP handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// List handles GET /api/etl/rules
func (h *Handler) List(c *gin.Context) {
	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)

	f := repository.ETLRuleListFilter{
		TenantID: tid,
		Page:     1,
		PageSize: 50,
	}
	if v := c.Query("dataset"); v != "" {
		f.Dataset = v
	}
	if v := c.Query("enabled"); v == "true" {
		t := true
		f.IsEnabled = &t
	} else if v == "false" {
		fv := false
		f.IsEnabled = &fv
	}

	rules, meta, err := h.svc.List(c.Request.Context(), f)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, rules, meta)
}

// Create handles POST /api/etl/rules
func (h *Handler) Create(c *gin.Context) {
	var rule model.ETLRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	tenantID, _ := c.Get("tenant_id")
	if tid, ok := tenantID.(string); ok && tid != "" {
		rule.TenantID = tid
	}
	uid, _ := c.Get("uid")
	operatorID, _ := uid.(string)

	if err := h.svc.Create(c.Request.Context(), &rule, operatorID); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Created(c, rule)
}

// Get handles GET /api/etl/rules/:id
func (h *Handler) Get(c *gin.Context) {
	key := c.Param("id")
	rule, err := h.svc.Get(c.Request.Context(), key)
	if err != nil {
		response.NotFound(c, err.Error())
		return
	}
	response.OK(c, rule)
}

// Update handles PATCH /api/etl/rules/:id
func (h *Handler) Update(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Update(c.Request.Context(), key, patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, gin.H{"updated": true})
}

// Delete handles DELETE /api/etl/rules/:id
func (h *Handler) Delete(c *gin.Context) {
	key := c.Param("id")
	if err := h.svc.Delete(c.Request.Context(), key); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

// Toggle handles PATCH /api/etl/rules/:id/toggle
// Flips the is_enabled field and returns the new state.
func (h *Handler) Toggle(c *gin.Context) {
	key := c.Param("id")
	enabled, err := h.svc.Toggle(c.Request.Context(), key)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "is_enabled": enabled})
}

// TestRequest is the body for POST /api/etl/rules/:id/test
type TestRequest struct {
	Tag    string          `json:"tag"`
	Sample model.LogEntry  `json:"sample"`
}

// Stats returns counts of ETL rules.
// GET /api/etl/rules/stats
func (h *Handler) Stats(c *gin.Context) {
	ctx := c.Request.Context()
	all, _, _ := h.svc.List(ctx, repository.ETLRuleListFilter{PageSize: 10000, Page: 1})
	var enabled, disabled int64
	for _, r := range all {
		if r.IsEnabled {
			enabled++
		} else {
			disabled++
		}
	}
	c.JSON(200, gin.H{
		"total":    int64(len(all)),
		"enabled":  enabled,
		"disabled": disabled,
	})
}

// Export returns all ETL rules as a JSON download.
// GET /api/etl/rules/export
func (h *Handler) Export(c *gin.Context) {
	ctx := c.Request.Context()
	rules, _, _ := h.svc.List(ctx, repository.ETLRuleListFilter{PageSize: 10000, Page: 1})
	c.Header("Content-Disposition", `attachment; filename="etl_rules.json"`)
	c.Header("Content-Type", "application/json")
	c.JSON(200, rules)
}

// Import creates multiple ETL rules from a JSON array.
// POST /api/etl/rules/import
func (h *Handler) Import(c *gin.Context) {
	operatorID := c.GetString(middleware.CtxUserID)
	var rules []model.ETLRule
	if err := c.ShouldBindJSON(&rules); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	var created, skipped int
	for i := range rules {
		rules[i].Key = "" // force new document
		if err := h.svc.Create(c.Request.Context(), &rules[i], operatorID); err != nil {
			skipped++
		} else {
			created++
		}
	}
	c.JSON(200, gin.H{"created": created, "skipped": skipped})
}

// Test handles POST /api/etl/rules/:id/test
// Runs the full pipeline against a sample event and returns routing decisions.
// Nothing is written to any storage backend.
func (h *Handler) Test(c *gin.Context) {
	key := c.Param("id")
	var req TestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if req.Tag == "" {
		req.Tag = "test"
	}
	// Inject tenant
	if tid, ok := c.Get("tenant_id"); ok {
		if s, ok := tid.(string); ok && req.Sample.TenantID == "" {
			req.Sample.TenantID = s
		}
	}

	result, err := h.svc.Test(c.Request.Context(), key, &req.Sample, req.Tag)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, result)
}
