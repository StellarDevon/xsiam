package response

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type PlaybookHandler struct {
	svc *PlaybookService
}

func NewPlaybookHandler(svc *PlaybookService) *PlaybookHandler {
	return &PlaybookHandler{svc: svc}
}

func (h *PlaybookHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), PlaybookListFilter{
		TenantID:    tenantID,
		Keyword:     c.Query("keyword"),
		TriggerType: c.Query("trigger_type"),
		Status:      c.Query("status"),
		Page:        page,
		PageSize:    pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *PlaybookHandler) Get(c *gin.Context) {
	pb, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "playbook")
		return
	}
	response.OK(c, pb)
}

func (h *PlaybookHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var pb model.Playbook
	if err := c.ShouldBindJSON(&pb); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	pb.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &pb, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, pb)
}

func (h *PlaybookHandler) Update(c *gin.Context) {
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

func (h *PlaybookHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *PlaybookHandler) Execute(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.Execute(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "status": "running"})
}
