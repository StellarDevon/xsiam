package datalake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type HECEvent struct {
	Time       int64          `json:"time"`
	Index      string         `json:"index"`
	Sourcetype string         `json:"sourcetype"`
	Event      map[string]any `json:"event"`
}

func (c *Client) ingest(ctx context.Context, events []HECEvent) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.hecURL+"/services/collector/event", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+c.hecToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("hec ingest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hec status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Ingest(ctx context.Context, events []HECEvent) error {
	return c.ingest(ctx, events)
}
