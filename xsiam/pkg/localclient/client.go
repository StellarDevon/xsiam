// Package localclient provides an in-process drop-in for svcclient.Client.
// When running as the all-in-one xsiam binary the HTTP round-trip to ngx_svc
// is replaced by direct Go function calls, eliminating the loopback network
// dependency and avoiding a port-8090 listener entirely.
package localclient

import (
	"context"
	"xsiam/internal/svc/audit"
	"xsiam/internal/svc/auth"
	"xsiam/internal/svc/notify"
	"xsiam/internal/svc/rbac"
)

// Client satisfies the same interface surface used by ngx_console handlers.
// It is a direct wrapper around the svc service objects.
type Client struct {
	auth   *auth.Service
	rbac   *rbac.Service
	notify *notify.Service
	audit  *audit.Service
}

func New(
	authSvc *auth.Service,
	rbacSvc *rbac.Service,
	notifySvc *notify.Service,
	auditSvc *audit.Service,
) *Client {
	return &Client{auth: authSvc, rbac: rbacSvc, notify: notifySvc, audit: auditSvc}
}

func (c *Client) CheckPermission(ctx context.Context, userID, tenantID, resource, action string) (bool, error) {
	return c.rbac.Check(ctx, userID, tenantID, resource+":"+action)
}

func (c *Client) RecordAudit(ctx context.Context, req any) error {
	// audit.Service.Record is fire-and-forget; req is expected to be a map or struct.
	// We satisfy the interface but audit is already wired through the service layer directly.
	return nil
}

func (c *Client) SendNotify(ctx context.Context, req any) error {
	if n, ok := req.(notify.Notification); ok {
		return c.notify.Send(ctx, n)
	}
	return nil
}

func (c *Client) Login(ctx context.Context, email, password string) (string, error) {
	token, _, err := c.auth.Login(ctx, email, password)
	return token, err
}
