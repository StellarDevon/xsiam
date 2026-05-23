package datalake

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type QueryResult struct {
	Rows      []map[string]any `json:"rows"`
	Events    []map[string]any `json:"events"`
	Total     int              `json:"total"`
	ElapsedMs int              `json:"elapsed_ms"`
	ScannedGB float64          `json:"scanned_gb"`
}

func (c *Client) Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*QueryResult, error) {
	reqURL := fmt.Sprintf("%s/services/search/jobs/export?search=%s&earliest=%d&latest=%d",
		c.queryURL, url.QueryEscape(spl2), fromTS, toTS)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ngx query: %w", err)
	}
	defer resp.Body.Close()

	var result QueryResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ngx query decode: %w", err)
	}
	if result.Events == nil {
		result.Events = result.Rows
	}
	return &result, nil
}
