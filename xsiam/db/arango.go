package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
)

// Connect creates and verifies an ArangoDB client using HTTP/1.1.
// It retries for up to 60 seconds to tolerate slow WSL/Docker startup.
func Connect(endpoints []string, username, password string) (arangodb.Client, error) {
	ep := connection.NewRoundRobinEndpoints(endpoints)
	conn := connection.NewHttpConnection(connection.HttpConfiguration{
		Endpoint:       ep,
		Authentication: connection.NewBasicAuth(username, password),
		ContentType:    connection.ApplicationJSON,
	})

	client := arangodb.NewClient(conn)

	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := client.Version(ctx)
		cancel()
		if err == nil {
			return client, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("ArangoDB not reachable after 60s: %w", err)
		}
		log.Printf("[db] ArangoDB not ready, retrying in 3s: %v", err)
		time.Sleep(3 * time.Second)
	}
}

// Database opens (or creates) the named database and ensures all collections exist.
func Database(ctx context.Context, client arangodb.Client, name string) (arangodb.Database, error) {
	exists, err := client.DatabaseExists(ctx, name)
	if err != nil {
		return nil, err
	}
	var arangoDB arangodb.Database
	if !exists {
		arangoDB, err = client.CreateDatabase(ctx, name, nil)
		if err != nil {
			return nil, err
		}
	} else {
		arangoDB, err = client.Database(ctx, name)
		if err != nil {
			return nil, err
		}
	}
	EnsureCollections(ctx, arangoDB)
	return arangoDB, nil
}

// EnsureCollections creates all required collections if they do not yet exist.
func EnsureCollections(ctx context.Context, db arangodb.Database) {
	docCols := []string{
		"alerts", "incidents", "assets", "vulnerabilities",
		"iocs", "intel_feeds", "actions", "devices", "agent_policies",
		"datasources", "playbooks", "reports", "users", "audit_logs",
		"tenants", "rbac_roles", "detection_rules",
		"identity_risks", "privilege_restrictions", "exposure_scores",
		"causality_nodes",
		// Log storage — one collection for all datasets, partitioned by the
		// dataset field.  TTL index on event_timestamp keeps hot data 90 days.
		"log_entries",
		// ETL pipeline rules
		"etl_rules",
	}
	for _, name := range docCols {
		ensureCollection(ctx, db, name, false)
	}
	ensureCollection(ctx, db, "causality_edges", true)
	ensureGraph(ctx, db, "causality_graph", "causality_edges",
		[]string{"causality_nodes"}, []string{"causality_nodes"})

	// TTL index on log_entries — expire after 90 days (7 776 000 seconds).
	ensureTTLIndex(ctx, db, "log_entries", "event_timestamp", 7_776_000)

	// etl_rules: compound index for hot-reload query (tenant + enabled + priority)
	ensurePersistentIndex(ctx, db, "etl_rules",
		[]string{"tenant_id", "is_enabled", "priority"})

	// Persistent indexes for common log query patterns.
	ensurePersistentIndex(ctx, db, "log_entries",
		[]string{"tenant_id", "dataset", "event_timestamp"})
	ensurePersistentIndex(ctx, db, "log_entries",
		[]string{"tenant_id", "agent_id", "event_timestamp"})
	ensurePersistentIndex(ctx, db, "log_entries",
		[]string{"tenant_id", "kind", "event_timestamp"})
}

func ensureCollection(ctx context.Context, db arangodb.Database, name string, isEdge bool) {
	exists, _ := db.CollectionExists(ctx, name)
	if exists {
		return
	}
	props := arangodb.CreateCollectionProperties{}
	if isEdge {
		props.Type = arangodb.CollectionTypeEdge
	}
	_, _ = db.CreateCollection(ctx, name, &props)
}

func ensureGraph(ctx context.Context, db arangodb.Database, graphName, edgeCol string, from, to []string) {
	exists, _ := db.GraphExists(ctx, graphName)
	if exists {
		return
	}
	graphDef := &arangodb.GraphDefinition{
		EdgeDefinitions: []arangodb.EdgeDefinition{{
			Collection: edgeCol,
			From:       from,
			To:         to,
		}},
	}
	_, _ = db.CreateGraph(ctx, graphName, graphDef, nil)
}

// ensureTTLIndex creates a TTL index on the named field of a collection.
// expireAfterSeconds controls how long after the field's value documents live.
// Already-existing indexes are silently skipped.
func ensureTTLIndex(ctx context.Context, db arangodb.Database, colName, field string, expireAfterSeconds int) {
	col, err := db.Collection(ctx, colName)
	if err != nil {
		log.Printf("[db] ensureTTLIndex: collection %s not found: %v", colName, err)
		return
	}
	// arangodb.Collection embeds CollectionIndexes — direct call is valid.
	if _, _, err = col.EnsureTTLIndex(ctx, []string{field}, expireAfterSeconds, nil); err != nil {
		log.Printf("[db] ensureTTLIndex %s.%s: %v", colName, field, err)
	}
}

// ensurePersistentIndex creates a persistent (sorted) index on the given fields.
func ensurePersistentIndex(ctx context.Context, db arangodb.Database, colName string, fields []string) {
	col, err := db.Collection(ctx, colName)
	if err != nil {
		log.Printf("[db] ensurePersistentIndex: collection %s not found: %v", colName, err)
		return
	}
	if _, _, err = col.EnsurePersistentIndex(ctx, fields, nil); err != nil {
		log.Printf("[db] ensurePersistentIndex %s %v: %v", colName, fields, err)
	}
}
