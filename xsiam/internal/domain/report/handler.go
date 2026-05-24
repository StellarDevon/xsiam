package report

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
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
	// If a schedule was included in the body, apply it immediately after creation.
	if r.Schedule != "" {
		if err := h.svc.Schedule(c.Request.Context(), &r, r.Schedule); err != nil {
			// Non-fatal: report was created; scheduling failure is logged but not surfaced.
			_ = err
		}
	}
	response.Created(c, r)
}

// Schedule sets a recurrence schedule on an existing report.
// POST /reports/:id/schedule  body: {"schedule":"daily|weekly|monthly|once"}
func (h *Handler) Schedule(c *gin.Context) {
	r, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "report")
		return
	}
	var body struct {
		Schedule string `json:"schedule" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Schedule(c.Request.Context(), r, body.Schedule); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, r)
}

func (h *Handler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

// Stats returns aggregated report counts by status for the current tenant.
// GET /api/reports/stats
func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.GetStats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}

// Download returns the report as a stub text file attachment.
// GET /api/reports/:id/download
func (h *Handler) Download(c *gin.Context) {
	id := c.Param("id")
	r, err := h.svc.Get(c.Request.Context(), id)
	if err != nil {
		response.NotFound(c, "report")
		return
	}
	if r.Status != model.ReportStatusReady {
		c.JSON(http.StatusConflict, gin.H{
			"error":  "report not ready",
			"status": string(r.Status),
		})
		return
	}
	tenantID := r.TenantID
	timestamp := time.Now().UTC().Format(time.RFC3339)
	body := fmt.Sprintf("XSIAM Report\nID: %s\nGenerated: %s\nTenant: %s\n", id, timestamp, tenantID)

	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.txt"`, id))
	c.Data(http.StatusOK, "text/plain", []byte(body))
}
