package query

import (
	"context"
	"xsiam/internal/datalake"
)

type Service struct {
	lakeClient datalake.QueryClient
}

func NewService(lakeClient datalake.QueryClient) *Service {
	return &Service{lakeClient: lakeClient}
}

func (s *Service) Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*datalake.QueryResult, error) {
	return s.lakeClient.Query(ctx, spl2, fromTS, toTS)
}

func (s *Service) Datasets(_ context.Context) []map[string]string {
	return []map[string]string{
		{"id": "xsiam_endpoint", "name": "Endpoint Events", "description": "Process, file, network events from endpoints"},
		{"id": "xsiam_network", "name": "Network Events", "description": "Firewall, proxy, IDS/IPS events"},
		{"id": "xsiam_identity", "name": "Identity Events", "description": "Auth logs, AD events, LDAP queries"},
		{"id": "xsiam_cloud", "name": "Cloud Events", "description": "Cloud provider audit logs"},
	}
}
