package notify

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler exposes the /notify/send endpoint for ngx_svc.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Send(c *gin.Context) {
	var n Notification
	if err := c.ShouldBindJSON(&n); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.Send(c.Request.Context(), n); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sent": true})
}
