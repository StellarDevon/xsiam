package query_test

import (
	"context"
	"testing"
	"xsiam/internal/datalake"
	"xsiam/internal/domain/query"
)

func TestQueryService_Datasets_ReturnsFour(t *testing.T) {
	svc := query.NewService(&datalake.DataLakeStub{})
	datasets := svc.Datasets(context.Background())
	if len(datasets) != 4 {
		t.Errorf("expected 4 datasets, got %d", len(datasets))
	}
	ids := make(map[string]bool)
	for _, d := range datasets {
		ids[d["id"]] = true
	}
	for _, want := range []string{"xsiam_endpoint", "xsiam_network", "xsiam_identity", "xsiam_cloud"} {
		if !ids[want] {
			t.Errorf("missing dataset id: %s", want)
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
