package device

// AgentEventHandler handles internal-port Agent lifecycle events.
//
// Endpoint:  POST /internal/agent/event
// Auth:      none (internal network only; no JWT required)
//
// Body (JSON):
//
//	{
//	  "agent_id":      "agent-00001",          // required
//	  "event":         "connect|disconnect|heartbeat",  // required
//	  "hostname":      "WIN-LAPTOP-01",         // optional; used on connect
//	  "ip_addresses":  ["10.0.0.55"],           // optional
//	  "os_type":       "windows",               // optional
//	  "os_version":    "11",                    // optional
//	  "agent_version": "7.4.2",                 // optional
//	  "policy_id":     "default",               // optional
//	  "tenant_id":     "default",               // optional
//	  "timestamp":     "2026-05-23T12:00:00Z"   // optional; defaults to server now
//	}
//
// Response 204 on success, 400/500 on error.

import (
	"net/http"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AgentEventInternalHandler sits on the :18090 internal engine.
type AgentEventInternalHandler struct {
	svc      *Service
	liveness *LivenessRegistry
	log      *zap.Logger
}

// NewAgentEventInternalHandler constructs the handler.
func NewAgentEventInternalHandler(svc *Service, liveness *LivenessRegistry, log *zap.Logger) *AgentEventInternalHandler {
	return &AgentEventInternalHandler{svc: svc, liveness: liveness, log: log}
}

// Handle processes POST /internal/agent/event.
func (h *AgentEventInternalHandler) Handle(c *gin.Context) {
	var ev AgentEvent
	if err := c.ShouldBindJSON(&ev); err != nil {
		response.BadRequest(c, err.Error())
		return
	}

	h.log.Info("agent event",
		zap.String("agent_id", ev.AgentID),
		zap.String("event", string(ev.Event)),
		zap.String("hostname", ev.Hostname),
	)

	if err := h.svc.HandleAgentEvent(c.Request.Context(), ev, h.liveness); err != nil {
		h.log.Warn("agent event error", zap.Error(err), zap.String("agent_id", ev.AgentID))
		// Non-fatal: liveness was already updated; DB failure shouldn't block the agent
		c.Status(http.StatusNoContent)
		return
	}

	c.Status(http.StatusNoContent)
}
