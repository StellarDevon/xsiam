package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
	"xsiam/internal/model"

	"go.uber.org/zap"
)

// WebhookEvent is the payload sent to SOAR or external systems when an
// incident crosses a severity/score threshold.
type WebhookEvent struct {
	EventType    string         `json:"event_type"`   // "incident.created" | "incident.escalated" | "incident.resolved"
	IncidentID   string         `json:"incident_id"`
	Name         string         `json:"name"`
	Severity     string         `json:"severity"`
	SmartScore   float64        `json:"smart_score"`
	Status       string         `json:"status"`
	AlertCount   int            `json:"alert_count"`
	AssetNames   []string       `json:"asset_names"`
	MitreTactics []string       `json:"mitre_tactics"`
	TriggeredAt  time.Time      `json:"triggered_at"`
	WebhookMeta  map[string]any `json:"meta,omitempty"`
}

// WebhookDispatcher sends incident events to configured endpoints.
type WebhookDispatcher struct {
	endpoints []string
	secret    string
	client    *http.Client
	log       *zap.Logger
	enabled   bool
}

func NewWebhookDispatcher(endpoints []string, secret string, log *zap.Logger) *WebhookDispatcher {
	return &WebhookDispatcher{
		endpoints: endpoints,
		secret:    secret,
		client:    &http.Client{Timeout: 10 * time.Second},
		log:       log,
		enabled:   len(endpoints) > 0,
	}
}

// ShouldNotify returns true when the incident warrants a webhook push.
// Fires for: new critical/high incidents, smart_score > 70, status transitions.
func (d *WebhookDispatcher) ShouldNotify(inc *model.Incident, eventType string) bool {
	if !d.enabled {
		return false
	}
	switch eventType {
	case "incident.created":
		return inc.Severity == model.SeverityCritical || inc.Severity == model.SeverityHigh || inc.SmartScore >= 70
	case "incident.escalated":
		return inc.SmartScore >= 80
	case "incident.resolved":
		return true
	}
	return false
}

// Dispatch sends the webhook asynchronously (non-blocking).
func (d *WebhookDispatcher) Dispatch(ctx context.Context, inc *model.Incident, eventType string) {
	if !d.ShouldNotify(inc, eventType) {
		return
	}
	event := WebhookEvent{
		EventType:    eventType,
		IncidentID:   inc.IncidentID,
		Name:         inc.Name,
		Severity:     string(inc.Severity),
		SmartScore:   inc.SmartScore,
		Status:       string(inc.Status),
		AlertCount:   inc.AlertCount,
		AssetNames:   inc.AffectedAssets,
		MitreTactics: inc.MitreTactics,
		TriggeredAt:  inc.CreatedAt,
	}
	go d.send(event)
}

func (d *WebhookDispatcher) send(event WebhookEvent) {
	body, _ := json.Marshal(event)
	for _, endpoint := range d.endpoints {
		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
		if err != nil {
			d.log.Warn("webhook: build request failed", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if d.secret != "" {
			req.Header.Set("X-XSIAM-Secret", d.secret)
		}
		req.Header.Set("X-XSIAM-Event", event.EventType)
		resp, err := d.client.Do(req)
		if err != nil {
			d.log.Warn("webhook: send failed", zap.String("endpoint", endpoint), zap.Error(err))
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			d.log.Info("webhook: sent", zap.String("event", event.EventType),
				zap.String("incident", event.IncidentID), zap.String("endpoint", endpoint))
		} else {
			d.log.Warn("webhook: non-2xx response",
				zap.String("endpoint", endpoint), zap.Int("status", resp.StatusCode))
		}
	}
}

// WebhookStatus returns configuration info for the dispatcher.
func (d *WebhookDispatcher) WebhookStatus() map[string]any {
	return map[string]any{
		"enabled":        d.enabled,
		"endpoint_count": len(d.endpoints),
		"has_secret":     d.secret != "",
	}
}

// InjectDispatcher wires a WebhookDispatcher into an existing Service.
// Call this after NewService.
func InjectDispatcher(svc *Service, dispatcher *WebhookDispatcher) {
	svc.webhookDispatcher = dispatcher
}
