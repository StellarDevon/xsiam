package query_test

import (
	"context"
	"testing"
	"xsiam/internal/datalake"
	"xsiam/internal/domain/query"
)

func TestQueryService_Datasets_ReturnsBuiltins(t *testing.T) {
	svc := query.NewService(&datalake.DataLakeStub{})
	datasets := svc.Datasets(context.Background())
	if len(datasets) == 0 {
		t.Fatalf("expected at least one dataset, got 0")
	}
	ids := make(map[string]bool)
	for _, d := range datasets {
		ids[d.ID] = true
	}
	// Core datasets that must always be present
	for _, want := range []string{"xdr_data", "network_story", "syslog_raw"} {
		if !ids[want] {
			t.Errorf("missing required dataset id: %s", want)
		}
	}
}

func TestQueryService_Query_ReturnsStubRows(t *testing.T) {
	svc := query.NewService(&datalake.DataLakeStub{})
	result, err := svc.Query(context.Background(), "SELECT * FROM endpoint LIMIT 10", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Total == 0 {
		t.Error("expected non-zero total from stub")
	}
}
