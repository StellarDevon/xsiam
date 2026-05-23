package svcclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Caller is the interface satisfied by both *Client (HTTP) and
// localclient.Client (in-process). Swap the concrete type to this
// interface to decouple callers from the HTTP transport.
type Caller interface {
	CheckPermission(ctx context.Context, userID, tenantID, resource, action string) (bool, error)
	RecordAudit(ctx context.Context, req any) error
	SendNotify(ctx context.Context, req any) error
	Login(ctx context.Context, email, password string) (string, error)
}

type Client struct {
	base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{
		base: base,
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) CheckPermission(ctx context.Context, userID, tenantID, resource, action string) (bool, error) {
	body, _ := json.Marshal(map[string]string{
		"user_id": userID, "tenant_id": tenantID, "resource": resource, "action": action,
	})
	resp, err := c.post(ctx, "/rbac/check", body)
	if err != nil {
		return false, err
	}
	var result struct {
		Allowed bool `json:"allowed"`
	}
	json.Unmarshal(resp, &result)
	return result.Allowed, nil
}

func (c *Client) RecordAudit(ctx context.Context, req any) error {
	body, _ := json.Marshal(req)
	_, err := c.post(ctx, "/audit/record", body)
	return err
}

func (c *Client) SendNotify(ctx context.Context, req any) error {
	body, _ := json.Marshal(req)
	_, err := c.post(ctx, "/notify/send", body)
	return err
}

func (c *Client) Login(ctx context.Context, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := c.post(ctx, "/auth/login", body)
	if err != nil {
		return "", err
	}
	var result struct {
		Token string `json:"token"`
	}
	json.Unmarshal(resp, &result)
	return result.Token, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ngx_svc %s: %d", path, resp.StatusCode)
	}
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return buf.Bytes(), nil
}
