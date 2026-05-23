package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"xsiam/config"
)

// DingTalkSender sends notifications to a DingTalk group bot webhook.
type DingTalkSender struct {
	cfg    config.DingTalkConfig
	client *http.Client
}

func NewDingTalkSender(cfg config.DingTalkConfig) *DingTalkSender {
	return &DingTalkSender{cfg: cfg, client: &http.Client{}}
}

func (s *DingTalkSender) Send(ctx context.Context, n Notification) error {
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": n.Subject,
			"text":  n.Body,
		},
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
		return fmt.Errorf("dingtalk webhook: %d", resp.StatusCode)
	}
	return nil
}
