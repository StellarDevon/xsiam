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
	sortParam := c.Query("sort")
	orderParam := c.Query("order")
	sortBy := c.Query("sort_by")
	sortDesc := c.Query("sort_desc") == "true"
	// "sort" + "order" query params take precedence over legacy "sort_by"/"sort_desc"
	if sortParam == "risk_score" {
		sortBy = "risk_score"
		sortDesc = orderParam == "desc"
	}

	data, meta, err := h.svc.List(c.Request.Context(), repository.AssetListFilter{
		TenantID:  tenantID,
		Type:      c.Query("type"),
		Status:    c.Query("status"),
		RiskLevel: c.Query("risk_level"),
		Tag:       c.Query("tag"),
		Keyword:   c.Query("keyword"),
		Page:      page,
		PageSize:  pageSize,
		SortBy:    sortBy,
		SortDesc:  sortDesc,
		SortOrder: orderParam,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// Stats returns summary statistics for assets.
// GET /api/assets/stats
func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.Stats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
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

// Bulk performs bulk operations on assets.
// POST /api/assets/bulk
func (h *Handler) Bulk(c *gin.Context) {
	var body struct {
		Action     string         `json:"action" binding:"required"`
		Keys       []string       `json:"keys"`
		IDs        []string       `json:"ids"`
		Tag        string         `json:"tag"`
		AssignedTo string         `json:"assigned_to"`
		Patch      map[string]any `json:"patch"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	// keys takes precedence; fall back to ids
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	if len(keys) == 0 {
		response.BadRequest(c, "keys or ids required")
		return
	}
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	ctx := c.Request.Context()

	var updated int
	for _, id := range keys {
		var err error
		switch body.Action {
		case "tag":
			if body.Tag != "" {
				err = h.svc.PushTag(ctx, tenantID, id, body.Tag)
			}
		case "delete":
			err = h.svc.Delete(ctx, id, operatorID)
		case "assign":
			err = h.svc.Update(ctx, id, map[string]any{"owner": body.AssignedTo}, operatorID)
		case "patch":
			if len(body.Patch) > 0 {
				err = h.svc.Update(ctx, id, body.Patch, operatorID)
			}
		default:
			response.BadRequest(c, "unknown action: "+body.Action)
			return
		}
		if err == nil {
			updated++
		}
	}
	response.OK(c, gin.H{"updated": updated})
}

// GET /assets/export
func (h *Handler) Export(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	assets, _, err := h.svc.List(c.Request.Context(), repository.AssetListFilter{
		TenantID: tenantID,
		Page:     1,
		PageSize: 10000,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	c.Header("Content-Disposition", `attachment; filename="assets.csv"`)
	c.Header("Content-Type", "text/csv; charset=utf-8")
	w := csv.NewWriter(c.Writer)
	defer w.Flush()
	_ = w.Write([]string{"Key", "Name", "Type", "IP", "OS", "Status", "RiskScore", "Tags"})
	for _, a := range assets {
		ip := a.IP
		if ip == "" && len(a.IPAddresses) > 0 {
			ip = a.IPAddresses[0]
		}
		os := a.OS
		if os == "" {
			os = a.OSInfo.Name
		}
		_ = w.Write([]string{
			a.Key,
			a.Name,
			string(a.Type),
			ip,
			os,
			a.Status,
			fmt.Sprintf("%.2f", a.RiskScore),
			strings.Join(a.Tags, "|"),
		})
	}
}
