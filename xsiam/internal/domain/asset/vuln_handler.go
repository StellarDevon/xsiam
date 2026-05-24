package asset

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
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
		AssetID:   c.Query("asset_id"),
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

// POST /vulnerabilities/bulk
// Body: { "action": "assign|status|due_date", "ids": [...], "assigned_to": "...", "fix_status": "...", "due_date": "..." }
func (h *VulnHandler) Bulk(c *gin.Context) {
	var body struct {
		Action     string   `json:"action" binding:"required"`
		IDs        []string `json:"ids" binding:"required,min=1"`
		AssignedTo string   `json:"assigned_to"`
		FixStatus  string   `json:"fix_status"`
		DueDate    string   `json:"due_date"`
		FixNotes   string   `json:"fix_notes"`
		FixEffort  string   `json:"fix_effort"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	patch := map[string]any{}
	switch body.Action {
	case "assign":
		patch["assigned_to"] = body.AssignedTo
	case "status":
		patch["fix_status"] = body.FixStatus
	case "due_date":
		patch["due_date"] = body.DueDate
	}
	if len(patch) == 0 {
		response.BadRequest(c, "no patch fields")
		return
	}
	updated := 0
	for _, id := range body.IDs {
		if err := h.svc.Update(c.Request.Context(), id, patch, ""); err == nil {
			updated++
		}
	}
	response.OK(c, gin.H{"updated": updated})
}

// GET /vulnerabilities/export
func (h *VulnHandler) Export(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	vulns, _, err := h.svc.List(c.Request.Context(), repository.VulnerabilityListFilter{
		TenantID: tenantID,
		PageSize: 10000,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	c.Header("Content-Disposition", `attachment; filename="vulnerabilities.csv"`)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"CVEID", "Title", "Severity", "CVSSScore", "FixStatus", "AssignedTo", "DueDate", "AffectedAssets"})
	for _, v := range vulns {
		_ = w.Write([]string{
			v.CveID, v.Title, string(v.Severity), fmt.Sprintf("%.1f", v.CvssScore),
			string(v.FixStatus), v.AssignedTo, v.DueDate,
			strings.Join(v.AffectedAssets, "|"),
		})
	}
}
