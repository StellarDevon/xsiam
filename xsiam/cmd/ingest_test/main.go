// ingest_test directly calls repository.LogEntryRepo.BulkCreate and then
// queries back to verify ArangoDB round-trip.
package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"xsiam/config"
	"xsiam/db"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	client, err := db.Connect(cfg.ArangoDB.Endpoints, cfg.ArangoDB.Username, cfg.ArangoDB.Password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	arangoDB, err := db.Database(ctx, client, cfg.ArangoDB.Database)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database: %v\n", err)
		os.Exit(1)
	}

	repo := repository.NewLogEntryRepo(arangoDB)

	now := time.Now().UTC()
	entries := []*model.LogEntry{
		{
			TenantID:       "t-super",
			Dataset:        model.DatasetEndpoint,
			Kind:           model.LogKindProcess,
			AgentID:        "10001",
			Hostname:       "ENDPOINT-REAL-01",
			SourceIP:       "10.5.1.77",
			Fields:         map[string]any{"process_name": "powershell.exe", "cmdline": "test direct insert"},
			EventTimestamp: now,
			IngestedAt:     now,
		},
	}

	fmt.Println("Testing BulkCreate...")
	if err := repo.BulkCreate(ctx, entries); err != nil {
		fmt.Fprintf(os.Stderr, "BulkCreate error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("BulkCreate: OK")

	// Also test single Create
	fmt.Println("Testing single Create...")
	single := &model.LogEntry{
		TenantID:       "t-super",
		Dataset:        model.DatasetEndpoint,
		Kind:           model.LogKindAuth,
		AgentID:        "10001",
		Hostname:       "ENDPOINT-REAL-01",
		SourceIP:       "10.5.1.77",
		Fields:         map[string]any{"user": "testuser", "result": "success"},
		EventTimestamp: now,
		IngestedAt:     now,
	}
	if err := repo.Create(ctx, single); err != nil {
		fmt.Fprintf(os.Stderr, "Create error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Create: OK (key=%s)\n", single.Key)

	// Now read back
	entries2, _, err := repo.List(ctx, repository.LogListOptions{
		TenantID: "t-super",
		Dataset:  model.DatasetEndpoint,
		AgentID:  "10001",
		PageSize: 10,
		Page:     1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "List error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("List(agent_id=10001): %d rows\n", len(entries2))
	for _, e := range entries2 {
		fmt.Printf("  key=%s kind=%d hostname=%s\n", e.Key, e.Kind, e.Hostname)
	}
}
