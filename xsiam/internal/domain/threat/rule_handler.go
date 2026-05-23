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
	coverage, err := h.svc.MitreCoverage(c.Request.Context())
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, coverage)
}
