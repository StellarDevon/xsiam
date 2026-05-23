package identity

import (
	"context"
	"strings"
	"sync"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

type RiskService struct {
	store    sync.Map
	riskRepo *repository.IdentityRiskRepo
	privRepo *repository.PrivilegeRestrictionRepo
}

func NewRiskService(riskRepo *repository.IdentityRiskRepo, privRepo *repository.PrivilegeRestrictionRepo) *RiskService {
	return &RiskService{riskRepo: riskRepo, privRepo: privRepo}
}

func (s *RiskService) Restore(ctx context.Context) error {
	all, err := s.riskRepo.ListAll(ctx)
	if err != nil {
		return err
	}
	for i := range all {
		s.store.Store(all[i].UserID, &all[i])
	}
	return nil
}

func (s *RiskService) AddSignal(ctx context.Context, tenantID, userID, username string, signal model.RiskSignal) {
	val, _ := s.store.LoadOrStore(userID, &model.IdentityRisk{
		UserID:   userID,
		TenantID: tenantID,
		Username: username,
	})
	risk := val.(*model.IdentityRisk)
	risk.RiskSignals = append(risk.RiskSignals, signal)
	risk.RiskScore = s.calcScore(risk.RiskSignals)
	risk.UpdatedAt = time.Now()
	s.store.Store(userID, risk)
	if risk.RiskScore >= 80 {
		s.autoRestrict(ctx, risk)
	}
}

func (s *RiskService) Get(_ context.Context, userID string) *model.IdentityRisk {
	val, ok := s.store.Load(userID)
	if !ok {
		return nil
	}
	return val.(*model.IdentityRisk)
}

func (s *RiskService) List(_ context.Context, tenantID, keyword string, page, pageSize int) ([]model.IdentityRisk, model.PageMeta) {
	var risks []model.IdentityRisk
	s.store.Range(func(_, val any) bool {
		r := val.(*model.IdentityRisk)
		if r.TenantID != tenantID {
			return true
		}
		if keyword != "" {
			kw := strings.ToLower(keyword)
			if !strings.Contains(strings.ToLower(r.Username), kw) &&
				!strings.Contains(strings.ToLower(r.UserID), kw) {
				return true
			}
		}
		risks = append(risks, *r)
		return true
	})
	for i := 0; i < len(risks); i++ {
		for j := i + 1; j < len(risks); j++ {
			if risks[j].RiskScore > risks[i].RiskScore {
				risks[i], risks[j] = risks[j], risks[i]
			}
		}
	}
	total := int64(len(risks))
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= len(risks) {
		return nil, model.PageMeta{Total: total, Page: page, PageSize: pageSize}
	}
	if end > len(risks) {
		end = len(risks)
	}
	pages := int((total + int64(pageSize) - 1) / int64(pageSize))
	return risks[start:end], model.PageMeta{Total: total, Page: page, PageSize: pageSize, Pages: pages}
}

func (s *RiskService) FlushToDB(ctx context.Context) {
	s.store.Range(func(_, val any) bool {
		_ = s.riskRepo.Upsert(ctx, val.(*model.IdentityRisk))
		return true
	})
}

func (s *RiskService) StartFlusher(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.FlushToDB(ctx)
			case <-ctx.Done():
				s.FlushToDB(context.Background())
				return
			}
		}
	}()
}

func (s *RiskService) calcScore(signals []model.RiskSignal) float64 {
	var total float64
	for _, sig := range signals {
		total += sig.Score
	}
	if total > 100 {
		return 100
	}
	return total
}

func (s *RiskService) autoRestrict(ctx context.Context, risk *model.IdentityRisk) {
	if s.privRepo == nil {
		return
	}
	existing, _ := s.privRepo.GetActiveByUserLevel(ctx, risk.UserID, 3)
	if existing != nil {
		return
	}
	_ = s.privRepo.Create(ctx, &model.PrivilegeRestriction{
		UserID:        risk.UserID,
		TenantID:      risk.TenantID,
		Level:         3,
		TriggerSignal: "itdr_auto",
		TriggerScore:  risk.RiskScore,
		IsActive:      true,
	})
}

type ExposureService struct {
	exposureRepo *repository.ExposureScoreRepo
	vulnRepo     *repository.VulnerabilityRepo
	assetRepo    *repository.AssetRepo
}

func NewExposureService(
	exposureRepo *repository.ExposureScoreRepo,
	vulnRepo *repository.VulnerabilityRepo,
	assetRepo *repository.AssetRepo,
) *ExposureService {
	return &ExposureService{exposureRepo: exposureRepo, vulnRepo: vulnRepo, assetRepo: assetRepo}
}

func (s *ExposureService) List(ctx context.Context, f repository.ExposureListFilter) ([]model.ExposureScore, model.PageMeta, error) {
	return s.exposureRepo.List(ctx, f)
}

func (s *ExposureService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.exposureRepo.Update(ctx, key, patch)
}

func (s *ExposureService) CalcPriorityScore(ctx context.Context, score *model.ExposureScore) error {
	score.PriorityScore = score.CvssScore * score.InWildFactor * score.ReachabilityFactor * score.AssetImportanceFactor
	if score.PriorityScore > 100 {
		score.PriorityScore = 100
	}
	return s.exposureRepo.Upsert(ctx, score)
}

func (s *ExposureService) RecalcAll(ctx context.Context, tenantID string) error {
	vulns, _, err := s.vulnRepo.List(ctx, repository.VulnerabilityListFilter{TenantID: tenantID, PageSize: 10000, Page: 1})
	if err != nil {
		return err
	}
	for _, v := range vulns {
		if v.FixStatus == model.VulnFixStatusFixed || v.FixStatus == model.VulnFixStatusAccepted {
			continue
		}
		inWild := 1.0
		if v.ExploitedInWild {
			inWild = 1.5
		}
		assetIDs := v.AffectedAssetIDs
		if len(assetIDs) == 0 {
			_ = s.CalcPriorityScore(ctx, &model.ExposureScore{
				TenantID: tenantID, CveID: v.CveID, CvssScore: v.CvssScore,
				InWildFactor: inWild, ReachabilityFactor: 1.0, AssetImportanceFactor: 1.0,
				FixStatus: model.FixStatus(v.FixStatus),
			})
			continue
		}
		for _, assetID := range assetIDs {
			assetImportance, reachability := 1.0, 1.0
			asset, err := s.assetRepo.GetByID(ctx, assetID)
			if err == nil && asset != nil {
				switch asset.RiskLevel {
				case "critical":
					assetImportance = 2.0
				case "high":
					assetImportance = 1.5
				case "medium":
					assetImportance = 1.2
				}
				if asset.Type == model.AssetTypeNetwork || asset.Type == model.AssetTypeCloud {
					reachability = 1.8
				}
			}
			score := &model.ExposureScore{
				TenantID: tenantID, AssetID: assetID, CveID: v.CveID,
				CvssScore: v.CvssScore, InWildFactor: inWild,
				ReachabilityFactor: reachability, AssetImportanceFactor: assetImportance,
				FixStatus: model.FixStatus(v.FixStatus),
			}
			if asset != nil {
				score.AssetName = asset.Name
			}
			_ = s.CalcPriorityScore(ctx, score)
		}
	}
	return nil
}
