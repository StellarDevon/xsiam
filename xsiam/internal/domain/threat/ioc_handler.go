package threat

import (
	"strconv"
	"strings"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type IocHandler struct {
	svc *IocService
}

func NewIocHandler(svc *IocService) *IocHandler {
	return &IocHandler{svc: svc}
}

func (h *IocHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), repository.IocListFilter{
		TenantID: tenantID,
		Type:     c.Query("type"),
		Verdict:  c.Query("verdict"),
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

func (h *IocHandler) Get(c *gin.Context) {
	ioc, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "ioc")
		return
	}
	response.OK(c, ioc)
}

func (h *IocHandler) Search(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	q := c.Query("q")
	if q == "" {
		response.BadRequest(c, "q is required")
		return
	}
	limit := 20
	if n, err2 := strconv.Atoi(c.DefaultQuery("limit", "20")); err2 == nil && n > 0 {
		limit = n
	}
	results, err := h.svc.Search(c.Request.Context(), tenantID, q, limit)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, results)
}

func (h *IocHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var ioc model.IOC
	if err := c.ShouldBindJSON(&ioc); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	ioc.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &ioc, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, ioc)
}

func (h *IocHandler) BulkImport(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		IOCs []model.IOC `json:"iocs" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	for i := range body.IOCs {
		body.IOCs[i].TenantID = tenantID
	}
	if err := h.svc.BulkImport(c.Request.Context(), body.IOCs, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"imported": len(body.IOCs)})
}

func (h *IocHandler) Update(c *gin.Context) {
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

func (h *IocHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

// Hunt looks up IOC records by one or more indicator values (IPs, hashes, domains, etc.).
// GET /api/iocs/hunt?values=ip1,ip2,hash1
func (h *IocHandler) Hunt(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	rawValues := c.Query("values")
	if rawValues == "" {
		response.BadRequest(c, "values query parameter is required")
		return
	}
	values := strings.Split(rawValues, ",")
	results, err := h.svc.Hunt(c.Request.Context(), tenantID, values)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	if results == nil {
		results = []model.IOC{}
	}
	response.OK(c, results)
}
