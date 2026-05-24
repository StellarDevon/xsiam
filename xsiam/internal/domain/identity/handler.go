package identity

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type RiskHandler struct {
	svc *RiskService
}

func NewRiskHandler(svc *RiskService) *RiskHandler {
	return &RiskHandler{svc: svc}
}

func (h *RiskHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	keyword := c.Query("keyword")
	data, meta := h.svc.List(c.Request.Context(), tenantID, keyword, page, pageSize)
	response.Paginated(c, data, meta)
}

func (h *RiskHandler) Get(c *gin.Context) {
	risk := h.svc.Get(c.Request.Context(), c.Param("user_id"))
	if risk == nil {
		response.NotFound(c, "identity_risk")
		return
	}
	response.OK(c, risk)
}

// Sessions handles GET /identity_sessions — returns active identity sessions
// derived from identity risks that have at least one active risk signal.
func (h *RiskHandler) Sessions(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	items, _ := h.svc.List(c.Request.Context(), tenantID, "", page, pageSize)
	// Filter to only risks with active signals
	active := make([]model.IdentityRisk, 0, len(items))
	for _, r := range items {
		if len(r.RiskSignals) > 0 {
			active = append(active, r)
		}
	}
	response.OK(c, gin.H{"items": active})
}

func (h *RiskHandler) AddSignal(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	userID := c.Param("user_id")
	var body struct {
		Username string           `json:"username"`
		Signal   model.RiskSignal `json:"signal" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	h.svc.AddSignal(c.Request.Context(), tenantID, userID, body.Username, body.Signal)
	response.OK(c, gin.H{"user_id": userID})
}

type ExposureHandler struct {
	svc *ExposureService
}

func NewExposureHandler(svc *ExposureService) *ExposureHandler {
	return &ExposureHandler{svc: svc}
}

func (h *ExposureHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	minScore, _ := strconv.ParseFloat(c.Query("min_score"), 64)
	maxScore, _ := strconv.ParseFloat(c.Query("max_score"), 64)
	data, meta, err := h.svc.List(c.Request.Context(), repository.ExposureListFilter{
		TenantID:     tenantID,
		Keyword:      c.Query("keyword"),
		FixStatus:    c.Query("status"),
		Reachability: c.Query("reachability"),
		InWild:       c.Query("in_wild"),
		MinScore:     minScore,
		MaxScore:     maxScore,
		CVEID:        c.Query("cve_id"),
		AssetID:      c.Query("asset_id"),
		Page:         page,
		PageSize:     pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *ExposureHandler) Update(c *gin.Context) {
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

// BulkUpdate POST /exposure_scores/bulk
// Accepts JSON body:
//
//	{ "action": "assign|set_deadline|set_status", "ids": [...],
//	  "assigned_to": "...", "deadline": "...", "status": "..." }
//
// For each ID, builds a patch map and calls repo.Update. Returns { "updated": N }.
func (h *ExposureHandler) BulkUpdate(c *gin.Context) {
	var body struct {
		Action     string   `json:"action" binding:"required"`
		IDs        []string `json:"ids"    binding:"required"`
		AssignedTo string   `json:"assigned_to"`
		Deadline   string   `json:"deadline"`
		Status     string   `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if len(body.IDs) == 0 {
		response.BadRequest(c, "ids must not be empty")
		return
	}

	patch := map[string]any{}
	switch body.Action {
	case "assign":
		if body.AssignedTo == "" {
			response.BadRequest(c, "assigned_to is required for action=assign")
			return
		}
		patch["assigned_to"] = body.AssignedTo
	case "set_deadline":
		if body.Deadline == "" {
			response.BadRequest(c, "deadline is required for action=set_deadline")
			return
		}
		patch["deadline"] = body.Deadline
	case "set_status":
		if body.Status == "" {
			response.BadRequest(c, "status is required for action=set_status")
			return
		}
		patch["fix_status"] = body.Status
	default:
		response.BadRequest(c, "action must be one of: assign, set_deadline, set_status")
		return
	}

	ctx := c.Request.Context()
	var updated int
	for _, id := range body.IDs {
		// Copy patch so each call gets its own map (repo.Update mutates updated_at)
		p := make(map[string]any, len(patch))
		for k, v := range patch {
			p[k] = v
		}
		if err := h.svc.Update(ctx, id, p); err == nil {
			updated++
		}
	}
	response.OK(c, gin.H{"updated": updated})
}

func (h *ExposureHandler) RecalcAll(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	if err := h.svc.RecalcAll(c.Request.Context(), tenantID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"status": "recalculated"})
}
