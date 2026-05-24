package incident

import (
	"context"
	"math"
	"sync"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// calculateWeightedScore computes a 0-100 smart score for an incident.
//
// Factors and weights:
//   - Severity        (40%): critical=1.0, high=0.7, medium=0.4, low=0.2
//   - Alert count     (20%): log10 scale, capped at 1.0 (≥20 alerts)
//   - Asset criticality (15%): fixed middle value 0.5
//   - MITRE depth     (15%): distinct tactic count / 5, capped at 1.0
//   - Age factor      (10%): >72h open → 1.0, >24h → 0.5, else 0
//
// Final score is rounded and clamped to [0, 100].
func calculateWeightedScore(inc *model.Incident, alertCount int) float64 {
	// Severity factor (40%)
	sevFactor := 0.5
	switch inc.Severity {
	case model.SeverityCritical:
		sevFactor = 1.0
	case model.SeverityHigh:
		sevFactor = 0.7
	case model.SeverityMedium:
		sevFactor = 0.4
	case model.SeverityLow:
		sevFactor = 0.2
	}

	// Alert count factor (20%): log scale, cap at 1.0
	alertFactor := math.Log10(float64(alertCount)+1) / math.Log10(21)
	if alertFactor > 1 {
		alertFactor = 1
	}

	// Asset factor (15%): fixed middle value for now
	assetFactor := 0.5

	// MITRE depth factor (15%): count distinct tactics
	tacticCount := len(inc.MitreTactics)
	if tacticCount == 0 && inc.MitreTactic != "" {
		tacticCount = 1
	}
	mitreFactor := math.Min(float64(tacticCount)/5.0, 1.0)

	// Age factor (10%): boost for open incidents past SLA
	ageFactor := 0.0
	ageH := time.Since(inc.FirstSeen).Hours()
	if ageH > 72 {
		ageFactor = 1.0
	} else if ageH > 24 {
		ageFactor = 0.5
	}

	raw := sevFactor*0.40 + alertFactor*0.20 + assetFactor*0.15 + mitreFactor*0.15 + ageFactor*0.10
	return math.Round(math.Min(raw*100, 100))
}

// SmartScoreEntry holds a cached score with its expiry.
type SmartScoreEntry struct {
	Score      float64            `json:"score"`
	Factors    map[string]float64 `json:"factors"`
	ComputedAt time.Time          `json:"computed_at"`
}

// SmartScoreIncidentStore is the incident interface needed by SmartScoreService.
type SmartScoreIncidentStore interface {
	GetByID(ctx context.Context, key string) (*model.Incident, error)
	Update(ctx context.Context, key string, patch map[string]any) error
	List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error)
	ListAlertKeys(ctx context.Context, incidentKey string) ([]string, error)
}

// SmartScoreAlertStore is the alert interface needed by SmartScoreService.
type SmartScoreAlertStore interface {
	FindByAlertID(ctx context.Context, id string) (*model.Alert, error)
}

// SmartScoreService maintains an in-process LRU-like cache of incident smart scores.
type SmartScoreService struct {
	mu           sync.RWMutex
	cache        map[string]*SmartScoreEntry
	ttl          time.Duration
	incidentRepo SmartScoreIncidentStore
	alertRepo    SmartScoreAlertStore
	aiEngine     *AIEngine
}

func NewSmartScoreService(
	incidentRepo SmartScoreIncidentStore,
	alertRepo    SmartScoreAlertStore,
	aiEngine     *AIEngine,
) *SmartScoreService {
	return &SmartScoreService{
		cache:        make(map[string]*SmartScoreEntry),
		ttl:          15 * time.Minute,
		incidentRepo: incidentRepo,
		alertRepo:    alertRepo,
		aiEngine:     aiEngine,
	}
}

// Calculate computes the smart score for an incident and caches the result.
// It fetches the live alert count via ListAlertKeys and applies severity
// propagation when the computed score crosses key thresholds.
func (s *SmartScoreService) Calculate(ctx context.Context, incidentKey string) (*SmartScoreEntry, error) {
	s.mu.RLock()
	entry, ok := s.cache[incidentKey]
	s.mu.RUnlock()
	if ok && time.Since(entry.ComputedAt) < s.ttl {
		return entry, nil
	}

	// 1. Fetch the incident.
	incident, err := s.incidentRepo.GetByID(ctx, incidentKey)
	if err != nil {
		return nil, err
	}

	// 2. Get alert count from the live index.
	alertKeys, err := s.incidentRepo.ListAlertKeys(ctx, incidentKey)
	if err != nil {
		return nil, err
	}
	alertCount := len(alertKeys)

	// 3. Compute weighted score.
	newScore := calculateWeightedScore(incident, alertCount)

	factors := map[string]float64{
		"severity":          incident.SmartScore, // preserved for API compatibility
		"alert_count":       float64(alertCount),
	}

	entry = &SmartScoreEntry{Score: newScore, Factors: factors, ComputedAt: time.Now()}
	s.mu.Lock()
	s.cache[incidentKey] = entry
	s.mu.Unlock()

	// 4. Persist the new score.
	_ = s.incidentRepo.Update(ctx, incidentKey, map[string]any{model.FieldIncidentSmartScore: newScore})

	// 5. Severity propagation.
	if newScore >= 80 && incident.Severity != model.SeverityCritical {
		_ = s.incidentRepo.Update(ctx, incidentKey, map[string]any{"severity": string(model.SeverityCritical)})
	} else if newScore >= 60 && incident.Severity == model.SeverityLow {
		_ = s.incidentRepo.Update(ctx, incidentKey, map[string]any{"severity": string(model.SeverityHigh)})
	}

	return entry, nil
}

// Get returns the cached score if available, otherwise recalculates.
func (s *SmartScoreService) Get(ctx context.Context, incidentKey string) (*SmartScoreEntry, error) {
	s.mu.RLock()
	entry, ok := s.cache[incidentKey]
	s.mu.RUnlock()
	if ok && time.Since(entry.ComputedAt) < s.ttl {
		return entry, nil
	}
	return s.Calculate(ctx, incidentKey)
}

// InvalidateAndRecalc evicts a cached score and synchronously recalculates.
func (s *SmartScoreService) InvalidateAndRecalc(ctx context.Context, incidentKey string) error {
	s.mu.Lock()
	delete(s.cache, incidentKey)
	s.mu.Unlock()
	_, err := s.Calculate(ctx, incidentKey)
	return err
}

// EvictExpired removes all cache entries older than the TTL.
func (s *SmartScoreService) EvictExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.cache {
		if now.Sub(v.ComputedAt) >= s.ttl {
			delete(s.cache, k)
		}
	}
}

// RecalcForTenant lists all open incidents for the given tenant and recalculates
// each incident's smart score. Returns the first error encountered, or nil.
func (s *SmartScoreService) RecalcForTenant(ctx context.Context, tenantID string) error {
	incidents, _, err := s.incidentRepo.List(ctx, repository.IncidentListFilter{
		TenantID: tenantID,
		Status:   "open",
		PageSize: 1000,
		Page:     1,
	})
	if err != nil {
		return err
	}
	for _, inc := range incidents {
		if err := s.InvalidateAndRecalc(ctx, inc.Key); err != nil {
			return err
		}
	}
	return nil
}

func (s *SmartScoreService) deriveFlags(_ context.Context, incident *model.Incident) map[string]bool {
	flags := map[string]bool{}

	if len(incident.AffectedAssets) > 0 {
		flags["critical_asset"] = true
	}

	for _, t := range incident.MitreTactics {
		switch t {
		case "lateral-movement", "TA0008":
			flags["lateral_movement"] = true
		case "exfiltration", "TA0010":
			flags["exfiltration"] = true
		case "command-and-control", "TA0011":
			flags["c2_communication"] = true
		}
	}

	if incident.AlertCount >= 10 {
		flags["high_volume"] = true
	}

	return flags
}
