package threat

import (
	"strconv"
	"time"
	"xsiam/internal/middleware"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type ThreatIntelHandler struct {
	ruleRepo   *RuleRepo
	iocRepo    *IocRepo
	reportRepo *repository.ReportRepo
}

func NewThreatIntelHandler(ruleRepo *RuleRepo, iocRepo *IocRepo, reportRepo *repository.ReportRepo) *ThreatIntelHandler {
	return &ThreatIntelHandler{ruleRepo: ruleRepo, iocRepo: iocRepo, reportRepo: reportRepo}
}

// Rules handles GET /threat_intel/rules — lists detection rules filtered by status and rule_type.
func (h *ThreatIntelHandler) Rules(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	status := c.Query("status")
	ruleType := c.DefaultQuery("rule_type", "")

	rules, meta, err := h.ruleRepo.List(c.Request.Context(), repository.DetectionRuleListFilter{
		TenantID: tenantID,
		Status:   status,
		RuleType: ruleType,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"items": rules, "meta": meta})
}

// Samples handles GET /threat_intel/samples — lists hash-type IOCs (malware samples).
func (h *ThreatIntelHandler) Samples(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	verdict := c.Query("verdict")

	iocs, meta, err := h.iocRepo.List(c.Request.Context(), repository.IocListFilter{
		TenantID: tenantID,
		Type:     "hash",
		Verdict:  verdict,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"items": iocs, "meta": meta})
}

// Sessions handles GET /threat_intel/sessions — returns active threat sessions
// derived from hash-type IOCs (malware samples) seen recently.
func (h *ThreatIntelHandler) Sessions(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	iocs, meta, err := h.iocRepo.List(c.Request.Context(), repository.IocListFilter{
		TenantID: tenantID,
		Type:     "hash",
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}

	type ThreatSession struct {
		SessionID  string    `json:"session_id"`
		Indicator  string    `json:"indicator"`
		IocType    string    `json:"ioc_type"`
		Verdict    string    `json:"verdict"`
		SeenAt     time.Time `json:"seen_at"`
		ThreatName string    `json:"threat_name"`
	}
	sessions := make([]ThreatSession, 0, len(iocs))
	for _, ioc := range iocs {
		sessions = append(sessions, ThreatSession{
			SessionID:  ioc.Key,
			Indicator:  ioc.Value,
			IocType:    string(ioc.Type),
			Verdict:    string(ioc.Verdict),
			SeenAt:     ioc.CreatedAt,
			ThreatName: ioc.ThreatName,
		})
	}
	response.OK(c, gin.H{"items": sessions, "meta": meta})
}

// Reports handles GET /threat_intel/reports — lists threat intelligence reports.
func (h *ThreatIntelHandler) Reports(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	reports, meta, err := h.reportRepo.List(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"items": reports, "meta": meta})
}
