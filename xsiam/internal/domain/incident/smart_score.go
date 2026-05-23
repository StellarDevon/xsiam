package incident

import (
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type SmartScoreHandler struct {
	svc *SmartScoreService
}

func NewSmartScoreHandler(svc *SmartScoreService) *SmartScoreHandler {
	return &SmartScoreHandler{svc: svc}
}

func (h *SmartScoreHandler) Get(c *gin.Context) {
	incidentKey := c.Param("id")
	entry, err := h.svc.Get(c.Request.Context(), incidentKey)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, entry)
}

func (h *SmartScoreHandler) Recalc(c *gin.Context) {
	incidentKey := c.Param("id")
	if err := h.svc.InvalidateAndRecalc(c.Request.Context(), incidentKey); err != nil {
		response.InternalError(c, err)
		return
	}
	entry, err := h.svc.Get(c.Request.Context(), incidentKey)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, entry)
}
