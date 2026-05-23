package report

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
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
	data, meta, err := h.svc.List(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *Handler) Get(c *gin.Context) {
	r, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "report")
		return
	}
	response.OK(c, r)
}

func (h *Handler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var r model.Report
	if err := c.ShouldBindJSON(&r); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	r.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &r, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, r)
}

func (h *Handler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}
