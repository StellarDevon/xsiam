package audit

import (
	"net/http"
	"time"
	"xsiam/internal/repository"

	"github.com/gin-gonic/gin"
)

// Handler exposes /audit/record and /audit/logs for ngx_svc.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Record(c *gin.Context) {
	var body struct {
		TenantID     string `json:"tenant_id"`
		OperatorID   string `json:"operator_id"`
		Action       string `json:"action"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		ResourceName string `json:"resource_name"`
		OldValue     any    `json:"old_value"`
		NewValue     any    `json:"new_value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.svc.Record(c.Request.Context(), body.TenantID, body.OperatorID, body.Action,
		body.ResourceType, body.ResourceID, body.ResourceName, body.OldValue, body.NewValue)
	c.JSON(http.StatusOK, gin.H{"recorded": true})
}

func (h *Handler) List(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	operatorID := c.Query("operator_id")
	f := repository.AuditLogListFilter{
		TenantID:   tenantID,
		OperatorID: operatorID,
	}
	if from := c.Query("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err == nil {
			f.From = &t
		}
	}
	if to := c.Query("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err == nil {
			f.To = &t
		}
	}
	data, meta, err := h.svc.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": meta})
}

// WebList is the public-API variant of List. It enforces tenant isolation by
// reading tenant_id from the JWT context (set by middleware.JWTAuth) rather
// than from a query parameter, so callers cannot query another tenant's logs.
func (h *Handler) WebList(c *gin.Context) {
	tenantID := c.GetString("tenant_id")
	operatorID := c.Query("operator_id")
	f := repository.AuditLogListFilter{
		TenantID:   tenantID,
		OperatorID: operatorID,
	}
	if from := c.Query("from"); from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err == nil {
			f.From = &t
		}
	}
	if to := c.Query("to"); to != "" {
		t, err := time.Parse(time.RFC3339, to)
		if err == nil {
			f.To = &t
		}
	}
	data, meta, err := h.svc.List(c.Request.Context(), f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data, "meta": meta})
}
