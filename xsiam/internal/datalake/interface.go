package datalake

import "context"

type QueryClient interface {
	Query(ctx context.Context, spl2 string, fromTS, toTS int64) (*QueryResult, error)
}

type DataLakeStub struct{}

func (s *DataLakeStub) Query(_ context.Context, _ string, _, _ int64) (*QueryResult, error) {
	return &QueryResult{
		Rows: []map[string]any{
			{"_time": "2026-05-22T09:41:02Z", "process_name": "rclone.exe", "host_ip": "10.0.5.22", "bytes_sent": 8924872704},
			{"_time": "2026-05-22T08:12:44Z", "process_name": "powershell.exe", "host_ip": "10.0.3.15", "bytes_sent": 412809216},
		},
		Total: 2, ElapsedMs: 800, ScannedGB: 2.3,
	}, nil
}
