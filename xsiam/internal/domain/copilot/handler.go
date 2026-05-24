package copilot

import (
	"net/http"
	"xsiam/internal/middleware"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Chat(c *gin.Context) {
	var req struct {
		Message string `json:"message" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "message is required")
		return
	}
	tenantID := c.GetString(middleware.CtxTenantID)
	result, err := h.svc.Chat(c.Request.Context(), ChatRequest{
		Message:  req.Message,
		TenantID: tenantID,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, result)
}

// NL2XQL converts a natural language query to XQL via the AI engine.
// POST /api/copilot/nl2xql
// Body: {"query": "find all failed logins in last 24 hours"}
// Returns: {"xql": "dataset = xdr_data | filter ...", "ai_enhanced": bool}
func (h *Handler) NL2XQL(c *gin.Context) {
	var req struct {
		Query string `json:"query" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "query is required")
		return
	}
	xql, err := h.svc.NL2XQL(c.Request.Context(), req.Query)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	aiEnhanced := h.svc.apiKey != ""
	c.JSON(http.StatusOK, gin.H{
		"xql":         xql,
		"ai_enhanced": aiEnhanced,
	})
}
