package response

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type ActionHandler struct {
	svc *ActionService
}

func NewActionHandler(svc *ActionService) *ActionHandler {
	return &ActionHandler{svc: svc}
}

func (h *ActionHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), repository.ActionListFilter{
		TenantID: tenantID,
		Status:   c.Query("status"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *ActionHandler) Get(c *gin.Context) {
	action, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "action")
		return
	}
	response.OK(c, action)
}

func (h *ActionHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var action model.Action
	if err := c.ShouldBindJSON(&action); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	action.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &action, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, action)
}

func (h *ActionHandler) Update(c *gin.Context) {
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

func (h *ActionHandler) Execute(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	if err := h.svc.Execute(c.Request.Context(), key, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key, "status": "running"})
}
