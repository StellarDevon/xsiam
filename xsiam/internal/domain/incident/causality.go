package incident

import (
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type CausalityHandler struct {
	svc *CausalityService
}

func NewCausalityHandler(svc *CausalityService) *CausalityHandler {
	return &CausalityHandler{svc: svc}
}

func (h *CausalityHandler) GetGraph(c *gin.Context) {
	incidentID := c.Param("incident_id")
	graph, err := h.svc.GetGraphByIncident(c.Request.Context(), incidentID)
	if err != nil {
		response.NotFound(c, "causality_graph")
		return
	}
	response.OK(c, graph)
}

func (h *CausalityHandler) Trigger(c *gin.Context) {
	var body struct {
		AlertID string `json:"alert_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.TriggerCorrelation(c.Request.Context(), body.AlertID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"triggered": body.AlertID})
}
