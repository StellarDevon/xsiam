package incident

import (
	"context"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/utils"

	"go.uber.org/zap"
)

const (
	DefaultTimeWindowH    = 24
	DefaultConfidenceMin  = 0.70
	MaxGraphNodes         = 500
	AutoIncidentMinAlerts = 2
)

// CausalityAlertStore is the alert interface needed by CausalityService.
type CausalityAlertStore interface {
	FindByAlertID(ctx context.Context, id string) (*model.Alert, error)
	FindByAssetSince(ctx context.Context, assetID *string, since time.Time) ([]*model.Alert, error)
	FindByIocValues(ctx context.Context, values []string, since time.Time) ([]*model.Alert, error)
	FindByUser(ctx context.Context, username *string, since time.Time) ([]*model.Alert, error)
	Update(ctx context.Context, key string, patch map[string]any) error
}

// CausalityIncidentStore is the incident interface needed by CausalityService.
type CausalityIncidentStore interface {
	Create(ctx context.Context, inc *model.Incident) error
}

// CausalityAssetStore is the asset interface needed by CausalityService.
type CausalityAssetStore interface {
	GetByID(ctx context.Context, key string) (*model.Asset, error)
}

// CausalityGraphStore is the graph interface needed by CausalityService.
type CausalityGraphStore interface {
	GetGraphByIncident(ctx context.Context, incidentID string) (*model.CausalityGraph, error)
	Upsert(ctx context.Context, graph *model.CausalityGraph) error
}

type CausalityService struct {
	graphRepo CausalityGraphStore
	alertRepo CausalityAlertStore
	incRepo   CausalityIncidentStore
	assetRepo CausalityAssetStore
}

func NewCausalityService(
	graphRepo CausalityGraphStore,
	alertRepo CausalityAlertStore,
	incRepo   CausalityIncidentStore,
	assetRepo CausalityAssetStore,
) *CausalityService {
	return &CausalityService{
		graphRepo: graphRepo,
		alertRepo: alertRepo,
		incRepo:   incRepo,
		assetRepo: assetRepo,
	}
}

func (s *CausalityService) TriggerCorrelation(ctx context.Context, triggerAlertID string) error {
	alert, err := s.alertRepo.FindByAlertID(ctx, triggerAlertID)
	if err != nil {
		return err
	}

	since := alert.TriggeredAt.Add(-time.Duration(DefaultTimeWindowH) * time.Hour)
	candidates := s.findCorrelatedAlerts(ctx, alert, since)
	if len(candidates) < AutoIncidentMinAlerts {
		return nil
	}

	graph := s.buildDAG(alert, candidates)
	if graph.Confidence < DefaultConfidenceMin {
		return nil
	}

	s.autoAggregateIncident(ctx, graph, candidates)
	return s.graphRepo.Upsert(ctx, graph)
}

func (s *CausalityService) findCorrelatedAlerts(ctx context.Context, root *model.Alert, since time.Time) []*model.Alert {
	byAsset, _ := s.alertRepo.FindByAssetSince(ctx, root.AssetID, since)
	var iocValues []string
	for _, ioc := range root.IOCs {
		iocValues = append(iocValues, ioc.Value)
	}
	byIoc, _ := s.alertRepo.FindByIocValues(ctx, iocValues, since)
	byUser, _ := s.alertRepo.FindByUser(ctx, root.UserName, since)
	return dedup(append(append(byAsset, byIoc...), byUser...))
}

func (s *CausalityService) buildDAG(root *model.Alert, alerts []*model.Alert) *model.CausalityGraph {
	nodes := make([]model.CausalityNode, 0)
	edges := make([]model.CausalityEdge, 0)
	seen := map[string]bool{}

	addAlert := func(a *model.Alert, isRoot bool) string {
		nid := "alert:" + a.AlertID
		if seen[nid] {
			return nid
		}
		seen[nid] = true
		nodes = append(nodes, model.CausalityNode{
			NodeID:      nid,
			Type:        model.NodeTypeAlert,
			Label:       a.Name,
			AlertID:     &a.AlertID,
			AssetID:     a.AssetID,
			IsRootCause: isRoot,
			Severity:    &a.Severity,
			CreatedAt:   time.Now(),
		})
		if a.AssetID != nil {
			anid := "asset:" + *a.AssetID
			if !seen[anid] {
				seen[anid] = true
				nodes = append(nodes, model.CausalityNode{
					NodeID:    anid,
					Type:      model.NodeTypeAsset,
					Label:     a.AssetName,
					CreatedAt: time.Now(),
				})
			}
			edges = append(edges, model.CausalityEdge{
				Type:   model.EdgeTypeTriggered,
				Weight: 1.0,
			})
		}
		return nid
	}

	rootID := addAlert(root, true)
	for _, a := range alerts {
		if a.AlertID == root.AlertID {
			continue
		}
		addAlert(a, false)
		edges = append(edges, model.CausalityEdge{
			Type:   model.EdgeTypeTriggered,
			Weight: s.calcEdgeWeight(root, a),
		})
	}
	_ = rootID

	if len(nodes) > MaxGraphNodes {
		nodes = nodes[:MaxGraphNodes]
	}

	confidence := s.calcGraphConfidence(nodes, edges)
	return &model.CausalityGraph{
		GraphID:     utils.GenerateGraphID(),
		TimeWindowH: DefaultTimeWindowH,
		Confidence:  confidence,
		Nodes:       nodes,
		Edges:       edges,
		NodeCount:   len(nodes),
		EdgeCount:   len(edges),
		GeneratedAt: time.Now(),
		CreatedAt:   time.Now(),
	}
}

func (s *CausalityService) calcEdgeWeight(a, b *model.Alert) float64 {
	w := 0.0
	if a.AssetID != nil && b.AssetID != nil && *a.AssetID == *b.AssetID {
		w += 0.4
	}
	for _, ta := range a.MitreTactics {
		for _, tb := range b.MitreTactics {
			if ta == tb {
				w += 0.3
				break
			}
		}
	}
	for _, ia := range a.IOCs {
		for _, ib := range b.IOCs {
			if ia.Value == ib.Value {
				w += 0.3
				break
			}
		}
	}
	if w > 1.0 {
		return 1.0
	}
	return w
}

func (s *CausalityService) calcGraphConfidence(nodes []model.CausalityNode, edges []model.CausalityEdge) float64 {
	if len(edges) == 0 {
		return 0
	}
	var total float64
	for _, e := range edges {
		total += e.Weight
	}
	avg := total / float64(len(edges))
	maxPossible := len(nodes) * (len(nodes) - 1) / 2
	if maxPossible < 1 {
		maxPossible = 1
	}
	density := float64(len(edges)) / float64(maxPossible)
	result := avg*0.7 + density*0.3
	if result > 1.0 {
		return 1.0
	}
	return result
}

func (s *CausalityService) autoAggregateIncident(ctx context.Context, graph *model.CausalityGraph, alerts []*model.Alert) {
	for _, a := range alerts {
		if a.IncidentID != nil {
			graph.IncidentID = *a.IncidentID
			return
		}
	}
	if len(alerts) >= AutoIncidentMinAlerts {
		inc := s.buildAutoIncident(alerts)
		_ = s.incRepo.Create(ctx, inc)
		graph.IncidentID = inc.IncidentID
		for _, a := range alerts {
			_ = s.alertRepo.Update(ctx, a.Key, map[string]any{"incident_id": inc.IncidentID})
		}
	}
}

func (s *CausalityService) buildAutoIncident(alerts []*model.Alert) *model.Incident {
	severity := model.SeverityLow
	for _, a := range alerts {
		if a.Severity > severity {
			severity = a.Severity
		}
	}
	var alertIDs []string
	for _, a := range alerts {
		alertIDs = append(alertIDs, a.AlertID)
	}
	now := time.Now()
	return &model.Incident{
		IncidentID:   utils.NewIncidentID(),
		Name:         "Auto-correlated Incident",
		Severity:     severity,
		Status:       model.IncidentStatusNew,
		AlertIDs:     alertIDs,
		AlertCount:   len(alertIDs),
		FirstSeen:    now,
		LastActivity: now,
	}
}

func (s *CausalityService) GetGraphByIncident(ctx context.Context, incidentID string) (*model.CausalityGraph, error) {
	return s.graphRepo.GetGraphByIncident(ctx, incidentID)
}

func dedup(alerts []*model.Alert) []*model.Alert {
	seen := map[string]bool{}
	result := make([]*model.Alert, 0)
	for _, a := range alerts {
		if !seen[a.AlertID] {
			seen[a.AlertID] = true
			result = append(result, a)
		}
	}
	return result
}

// CorrelationPool manages a pool of workers for alert correlation.
type CorrelationPool struct {
	queue chan string
	svc   *CausalityService
	log   *zap.Logger
}

func NewCorrelationPool(svc *CausalityService) *CorrelationPool {
	p := &CorrelationPool{
		queue: make(chan string, 4096),
		svc:   svc,
		log:   zap.L(),
	}
	for i := 0; i < 4; i++ {
		go p.worker()
	}
	return p
}

func (p *CorrelationPool) worker() {
	for alertID := range p.queue {
		_ = p.svc.TriggerCorrelation(context.Background(), alertID)
	}
}

func (p *CorrelationPool) Submit(alertID string) {
	select {
	case p.queue <- alertID:
	default:
		p.log.Warn("correlation queue full, dropped", zap.String("alert_id", alertID))
	}
}

func (p *CorrelationPool) Shutdown() {
	close(p.queue)
}

// AlertListFilter alias for use in cron tasks.
type AlertListFilter = repository.AlertListFilter
