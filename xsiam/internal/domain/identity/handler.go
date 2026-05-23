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
	data, meta, err := h.svc.List(c.Request.Context(), repository.ExposureListFilter{
		TenantID:     tenantID,
		Keyword:      c.Query("keyword"),
		FixStatus:    c.Query("status"),
		Reachability: c.Query("reachability"),
		InWild:       c.Query("in_wild"),
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

func (h *ExposureHandler) RecalcAll(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	if err := h.svc.RecalcAll(c.Request.Context(), tenantID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"status": "recalculated"})
}
