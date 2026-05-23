package datalake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type SavedSearch struct {
	Name            string `json:"name"`
	Search          string `json:"search"`
	CronExpr        string `json:"cron_expr"`
	AlertType       string `json:"alert.type"`
	AlertComparator string `json:"alert.comparator"`
	AlertThreshold  string `json:"alert.threshold"`
	WebhookURL      string `json:"webhook_url"`
	ActionWebhook   int    `json:"action.webhook"`
}

func (c *Client) CreateSavedSearch(ctx context.Context, ss SavedSearch) error {
	body, _ := json.Marshal(map[string]any{
		"name":             ss.Name,
		"search":           ss.Search,
		"cron_schedule":    ss.CronExpr,
		"alert.type":       ss.AlertType,
		"alert.comparator": ss.AlertComparator,
		"alert.threshold":  ss.AlertThreshold,
		"action.webhook":   ss.ActionWebhook,
		"webhook_url":      ss.WebhookURL,
		"enable_sched":     1,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.queryURL+"/services/saved_searches", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+c.hecToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("create saved search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ngx saved_search register: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) DeleteSavedSearch(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.queryURL+"/services/saved_searches/"+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+c.hecToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("delete saved search: %w", err)
	}
	defer resp.Body.Close()
	return nil
}
