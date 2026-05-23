package incident

import (
	"context"
	"sync"
	"time"
	"xsiam/internal/model"
)

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
func (s *SmartScoreService) Calculate(ctx context.Context, incidentKey string) (*SmartScoreEntry, error) {
	s.mu.RLock()
	entry, ok := s.cache[incidentKey]
	s.mu.RUnlock()
	if ok && time.Since(entry.ComputedAt) < s.ttl {
		return entry, nil
	}

	incident, err := s.incidentRepo.GetByID(ctx, incidentKey)
	if err != nil {
		return nil, err
	}

	factors := map[string]float64{}
	if len(incident.ScoreFactors) > 0 {
		for _, f := range incident.ScoreFactors {
			factors[f.Dimension] = f.Value
		}
	} else {
		flags := s.deriveFlags(ctx, incident)
		result := s.aiEngine.CalcSmartScore(flags)
		for _, f := range result.Factors {
			factors[f.Name] = f.Score
		}
	}

	score := incident.SmartScore
	if score == 0 {
		flags := s.deriveFlags(ctx, incident)
		result := s.aiEngine.CalcSmartScore(flags)
		score = result.Score
	}

	entry = &SmartScoreEntry{Score: score, Factors: factors, ComputedAt: time.Now()}
	s.mu.Lock()
	s.cache[incidentKey] = entry
	s.mu.Unlock()

	_ = s.incidentRepo.Update(ctx, incidentKey, map[string]any{"smart_score": score})
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

func (s *SmartScoreService) deriveFlags(ctx context.Context, incident *model.Incident) map[string]bool {
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
