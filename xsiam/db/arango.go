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
	}
	for _, name := range docCols {
		ensureCollection(ctx, db, name, false)
	}
	ensureCollection(ctx, db, "causality_edges", true)
	ensureGraph(ctx, db, "causality_graph", "causality_edges",
		[]string{"causality_nodes"}, []string{"causality_nodes"})
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
