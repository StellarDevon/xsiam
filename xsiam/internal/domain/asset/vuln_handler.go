package asset

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type VulnHandler struct {
	svc *VulnService
}

func NewVulnHandler(svc *VulnService) *VulnHandler {
	return &VulnHandler{svc: svc}
}

func (h *VulnHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), repository.VulnerabilityListFilter{
		TenantID:  tenantID,
		Severity:  c.Query("severity"),
		FixStatus: c.Query("fix_status"),
		Keyword:   c.Query("keyword"),
		Page:      page,
		PageSize:  pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *VulnHandler) Get(c *gin.Context) {
	v, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "vulnerability")
		return
	}
	response.OK(c, v)
}

func (h *VulnHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var v model.Vulnerability
	if err := c.ShouldBindJSON(&v); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	v.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &v, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, v)
}

func (h *VulnHandler) Update(c *gin.Context) {
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

func (h *VulnHandler) Delete(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.Delete(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *VulnHandler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.Stats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}
