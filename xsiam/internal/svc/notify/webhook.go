package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"xsiam/config"
)

// WebhookSender sends notifications to one or more generic webhook URLs via HTTP POST.
// The payload is the standard JSON representation of the Notification struct.
type WebhookSender struct {
	cfg    config.WebhookNotifyConfig
	client *http.Client
}

func NewWebhookSender(cfg config.WebhookNotifyConfig) *WebhookSender {
	return &WebhookSender{cfg: cfg, client: &http.Client{}}
}

func (s *WebhookSender) Send(ctx context.Context, n Notification) error {
	if len(s.cfg.URLs) == 0 {
		return fmt.Errorf("notify webhook: no URLs configured")
	}

	body, err := json.Marshal(n)
	if err != nil {
		return err
	}

	var firstErr error
	for _, url := range s.cfg.URLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			e := fmt.Errorf("notify webhook: %s returned %d", url, resp.StatusCode)
			if firstErr == nil {
				firstErr = e
			}
		}
	}
	return firstErr
}
