// Package network implements the Network Security domain:
// traffic stats, suspicious connections, DNS analysis, network asset inventory,
// and network-layer threat detection rules.
package network

import (
	"net/http"
	"strconv"
	"time"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

// Handler handles all /api/network/* endpoints.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ─── GET /api/network/stats ───────────────────────────────────────────────────

func (h *Handler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	stats, err := h.svc.Stats(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, stats)
}

// ─── Suspicious Connections ───────────────────────────────────────────────────

// ListConnections godoc
// GET /api/network/connections
func (h *Handler) ListConnections(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListConnections(c.Request.Context(), tenantID, page, pageSize, c.Query("status"), c.Query("severity"))
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// BlockConnection godoc
// POST /api/network/connections/block
// Body: { "id": "<_key>" }
func (h *Handler) BlockConnection(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		ID string `json:"id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.BlockConnection(c.Request.Context(), tenantID, body.ID, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": body.ID, "status": string(model.ConnStatusBlocked)})
}

// ─── DNS Records ──────────────────────────────────────────────────────────────

// ListDNS godoc
// GET /api/network/dns
func (h *Handler) ListDNS(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	data, meta, err := h.svc.ListDNS(c.Request.Context(), tenantID, page, pageSize, c.Query("risk"), c.Query("q"))
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// AddDNSBlocklist godoc
// POST /api/network/dns/blocklist
// Body: { "domain": "evil.com" }
func (h *Handler) AddDNSBlocklist(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var body struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.AddDNSBlocklist(c.Request.Context(), tenantID, body.Domain, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"domain": body.Domain, "blocklisted": true})
}

// ─── Network Detection Rules ──────────────────────────────────────────────────

// ListNetworkRules godoc
// GET /api/network/detection_rules
func (h *Handler) ListNetworkRules(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	data, err := h.svc.ListNetworkRules(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"items": data, "total": len(data)})
}

// UpdateNetworkRule godoc
// PATCH /api/network/detection_rules/:id
// Body: { "active": true }
func (h *Handler) UpdateNetworkRule(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpdateNetworkRule(c.Request.Context(), tenantID, key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

// ─── Network Threat Alerts ────────────────────────────────────────────────────

// ListNetworkAlerts godoc
// GET /api/network/alerts
func (h *Handler) ListNetworkAlerts(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.ListNetworkAlerts(c.Request.Context(), tenantID, page, pageSize, c.Query("status"))
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// UpdateNetworkAlert godoc
// PATCH /api/network/alerts/:id
func (h *Handler) UpdateNetworkAlert(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.UpdateNetworkAlert(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

// ─── Network Devices (passive NTA asset inventory) ────────────────────────────

// ListNetworkDevices godoc
// GET /api/network/devices
func (h *Handler) ListNetworkDevices(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	data, meta, err := h.svc.ListNetworkDevices(c.Request.Context(), tenantID, page, pageSize,
		c.Query("device_type"), c.Query("risk"), c.Query("q"))
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

// ─── 24h Traffic Timeline (for the chart) ────────────────────────────────────

type TrafficPoint struct {
	Hour    string  `json:"hour"`
	InboundGB  float64 `json:"inbound_gb"`
	OutboundGB float64 `json:"outbound_gb"`
}

// TrafficTimeline godoc
// GET /api/network/traffic/timeline
func (h *Handler) TrafficTimeline(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	points, err := h.svc.TrafficTimeline(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": points, "generated_at": time.Now().UTC()})
}
