package incident

import (
	"context"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const (
	colCausalityNodes = "causality_nodes"
	colCausalityEdges = "causality_edges"
)

// CausalityRepo is the ArangoDB-backed causality graph repository.
type CausalityRepo struct {
	db arangodb.Database
}

func NewCausalityRepo(db arangodb.Database) *CausalityRepo {
	return &CausalityRepo{db: db}
}

func (r *CausalityRepo) GetGraphByIncident(ctx context.Context, incidentID string) (*model.CausalityGraph, error) {
	nodesQuery := `FOR doc IN causality_nodes FILTER doc.incident_id == @incidentID RETURN doc`
	nodesCursor, err := r.db.Query(ctx, nodesQuery, &arangodb.QueryOptions{
		BindVars: map[string]any{"incidentID": incidentID},
	})
	if err != nil {
		return nil, err
	}
	defer nodesCursor.Close()

	var nodes []model.CausalityNode
	for nodesCursor.HasMore() {
		var n model.CausalityNode
		if _, err = nodesCursor.ReadDocument(ctx, &n); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}

	edgesQuery := `FOR doc IN causality_edges FILTER doc.incident_id == @incidentID RETURN doc`
	edgesCursor, err := r.db.Query(ctx, edgesQuery, &arangodb.QueryOptions{
		BindVars: map[string]any{"incidentID": incidentID},
	})
	if err != nil {
		return nil, err
	}
	defer edgesCursor.Close()

	var edges []model.CausalityEdge
	for edgesCursor.HasMore() {
		var e model.CausalityEdge
		if _, err = edgesCursor.ReadDocument(ctx, &e); err != nil {
			return nil, err
		}
		edges = append(edges, e)
	}

	return &model.CausalityGraph{
		IncidentID:  incidentID,
		Nodes:       nodes,
		Edges:       edges,
		NodeCount:   len(nodes),
		EdgeCount:   len(edges),
		GeneratedAt: time.Now(),
	}, nil
}

func (r *CausalityRepo) Upsert(ctx context.Context, graph *model.CausalityGraph) error {
	nodeCol, err := r.db.Collection(ctx, colCausalityNodes)
	if err != nil {
		return err
	}
	edgeCol, err := r.db.Collection(ctx, colCausalityEdges)
	if err != nil {
		return err
	}

	for i := range graph.Nodes {
		graph.Nodes[i].CreatedAt = time.Now()
		meta, err := nodeCol.CreateDocument(ctx, graph.Nodes[i])
		if err != nil {
			continue
		}
		graph.Nodes[i].Key = meta.Key
	}

	for i := range graph.Edges {
		_, _ = edgeCol.CreateDocument(ctx, graph.Edges[i])
	}
	return nil
}
