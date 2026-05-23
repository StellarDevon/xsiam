package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"xsiam/config"
)

// SlackSender sends notifications to a Slack incoming webhook.
type SlackSender struct {
	cfg    config.SlackConfig
	client *http.Client
}

func NewSlackSender(cfg config.SlackConfig) *SlackSender {
	return &SlackSender{cfg: cfg, client: &http.Client{}}
}

func (s *SlackSender) Send(ctx context.Context, n Notification) error {
	text := fmt.Sprintf("*%s*\n%s", n.Subject, n.Body)
	payload := map[string]any{
		"text": text,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack webhook: %d", resp.StatusCode)
	}
	return nil
}
