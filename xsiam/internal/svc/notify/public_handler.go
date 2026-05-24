package notify

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// PublicHandler exposes admin-facing notify endpoints on the public API.
type PublicHandler struct {
	svc *Service
}

// NewPublicHandler creates a PublicHandler backed by the given Service.
func NewPublicHandler(svc *Service) *PublicHandler {
	return &PublicHandler{svc: svc}
}

// testRequest is the JSON body for POST /api/notify/test.
type testRequest struct {
	Channel string `json:"channel" binding:"required"`
	Message string `json:"message" binding:"required"`
}

// Test sends a test notification on the requested channel and returns the result.
// POST /api/notify/test
// Body: { "channel": "email|dingtalk|slack|webhook", "message": "test message" }
func (h *PublicHandler) Test(c *gin.Context) {
	var req testRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	n := Notification{
		Channel: req.Channel,
		Subject: "Notification Test",
		Body:    req.Message,
	}

	if err := h.svc.Send(c.Request.Context(), n); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "sent",
		"channel": req.Channel,
	})
}
