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
	incidentID := c.Param("id")
	graph, err := h.svc.GetGraphByIncident(c.Request.Context(), incidentID)
	if err != nil {
		response.NotFound(c, "causality_graph")
		return
	}
	response.OK(c, graph)
}

// BulkCorrelate handles POST /incidents/bulk_correlate — runs correlation for each supplied alert ID.
// Body: { "alert_ids": ["id1", "id2", ...] }
func (h *CausalityHandler) BulkCorrelate(c *gin.Context) {
	var body struct {
		AlertIDs []string `json:"alert_ids" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	errs := h.svc.BulkCorrelate(c.Request.Context(), body.AlertIDs)
	failed := make([]string, 0, len(errs))
	for _, e := range errs {
		failed = append(failed, e.Error())
	}
	response.OK(c, gin.H{
		"processed": len(body.AlertIDs),
		"errors":    failed,
	})
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
