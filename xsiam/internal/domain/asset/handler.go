package asset

import (
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
	data, meta, err := h.svc.List(c.Request.Context(), repository.AssetListFilter{
		TenantID:  tenantID,
		Type:      c.Query("type"),
		Status:    c.Query("status"),
		RiskLevel: c.Query("risk_level"),
		Keyword:   c.Query("keyword"),
		Page:      page,
		PageSize:  pageSize,
		SortBy:    c.Query("sort_by"),
		SortDesc:  c.Query("sort_desc") == "true",
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	all, _, err := h.svc.List(c.Request.Context(), repository.AssetListFilter{TenantID: tenantID, PageSize: 10000, Page: 1})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	stats := map[string]int64{"total": int64(len(all))}
	for _, a := range all {
		stats["total_"+string(a.Type)]++
		if a.RiskLevel == "critical" {
			stats["critical_risk"]++
		}
	}
	response.OK(c, map[string]any{
		"total":           stats["total"],
		"critical_risk":   stats["critical_risk"],
		"total_endpoints": stats["total_endpoint"] + stats["total_workstation"] + stats["total_server"],
		"active_users":    stats["total_user"],
		"cloud_assets":    stats["total_cloud"],
	})
}

func (h *Handler) Get(c *gin.Context) {
	a, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "asset")
		return
	}
	response.OK(c, a)
}

func (h *Handler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var a model.Asset
	if err := c.ShouldBindJSON(&a); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	a.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &a, operatorID); err != nil {
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

func (h *Handler) Delete(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.Delete(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}
