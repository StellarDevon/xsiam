package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler exposes the RBAC check endpoint for ngx_svc.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Check(c *gin.Context) {
	var body struct {
		UserID   string `json:"user_id" binding:"required"`
		TenantID string `json:"tenant_id" binding:"required"`
		Resource string `json:"resource" binding:"required"`
		Action   string `json:"action" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	permission := body.Resource + ":" + body.Action
	allowed, err := h.svc.Check(c.Request.Context(), body.UserID, body.TenantID, permission)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"allowed": allowed})
}
