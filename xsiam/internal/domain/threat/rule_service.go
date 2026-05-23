package threat

import (
	"context"
	"fmt"
	"strings"
	"time"
	"xsiam/config"
	"xsiam/internal/datalake"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

type RuleService struct {
	ruleRepo   *RuleRepo
	lakeClient datalake.QueryClient
	lakeWriter *datalake.Client
	auditRepo  AuditLogger
	cfg        *config.Config
}

func NewRuleService(
	ruleRepo *RuleRepo,
	lakeClient datalake.QueryClient,
	lakeWriter *datalake.Client,
	auditRepo AuditLogger,
	cfg *config.Config,
) *RuleService {
	return &RuleService{
		ruleRepo:   ruleRepo,
		lakeClient: lakeClient,
		lakeWriter: lakeWriter,
		auditRepo:  auditRepo,
		cfg:        cfg,
	}
}

func (s *RuleService) List(ctx context.Context, f repository.DetectionRuleListFilter) ([]model.DetectionRule, model.PageMeta, error) {
	return s.ruleRepo.List(ctx, f)
}

func (s *RuleService) Get(ctx context.Context, key string) (*model.DetectionRule, error) {
	return s.ruleRepo.GetByID(ctx, key)
}

func (s *RuleService) Create(ctx context.Context, rule *model.DetectionRule, operatorID string) error {
	rule.Status = model.RuleStatusDraft
	rule.CreatedBy = operatorID
	return s.ruleRepo.Create(ctx, rule)
}

func (s *RuleService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.ruleRepo.Update(ctx, key, patch)
}

func (s *RuleService) Delete(ctx context.Context, key string) error {
	rule, err := s.ruleRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	if rule.Status == model.RuleStatusActive && s.lakeWriter != nil {
		_ = s.lakeWriter.DeleteSavedSearch(ctx, rule.Name)
	}
	return s.ruleRepo.Delete(ctx, key)
}

func (s *RuleService) TransitionStatus(ctx context.Context, key, newStatus, operatorID string) error {
	rule, err := s.ruleRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	target := model.RuleStatus(newStatus)
	allowed := model.RuleStatusTransitions[rule.Status]
	valid := false
	for _, a := range allowed {
		if a == target {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid status transition: %s -> %s", rule.Status, target)
	}

	if err = s.ruleRepo.UpdateStatus(ctx, key, newStatus, operatorID); err != nil {
		return err
	}

	if s.lakeWriter != nil {
		if target == model.RuleStatusActive {
			spl2 := s.RuleToSPL2(rule)
			webhookURL := ""
			if s.cfg != nil && s.cfg.WebhookURL != "" {
				webhookURL = s.cfg.WebhookURL
			}
			_ = s.lakeWriter.CreateSavedSearch(ctx, datalake.SavedSearch{
				Name:            rule.Name,
				Search:          spl2,
				CronExpr:        "*/5 * * * *",
				AlertType:       "number of events",
				AlertComparator: "greater than",
				AlertThreshold:  "0",
				WebhookURL:      webhookURL,
				ActionWebhook:   1,
			})
		} else if target == model.RuleStatusDisabled || target == model.RuleStatusDeprecated {
			_ = s.lakeWriter.DeleteSavedSearch(ctx, rule.Name)
		}
	}

	return nil
}

func (s *RuleService) TestReplay(ctx context.Context, key string, timeRangeH int) (*model.RuleTestResult, error) {
	rule, err := s.ruleRepo.GetByID(ctx, key)
	if err != nil {
		return nil, err
	}

	spl2 := s.RuleToSPL2(rule)
	now := time.Now()
	from := now.Add(-time.Duration(timeRangeH) * time.Hour)

	result, err := s.lakeClient.Query(ctx, spl2, from.UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, err
	}

	testResult := &model.RuleTestResult{
		MatchCount: len(result.Rows),
		TestedAt:   now,
		TimeRangeH: timeRangeH,
	}

	_ = s.ruleRepo.Update(ctx, key, map[string]any{
		"test_result": testResult,
	})

	return testResult, nil
}

func (s *RuleService) MitreCoverage(ctx context.Context) (map[string][]string, error) {
	return s.ruleRepo.AggregateByMitre(ctx)
}

func (s *RuleService) RuleToSPL2(rule *model.DetectionRule) string {
	def := rule.Definition
	switch rule.RuleType {
	case model.RuleTypeBIOC:
		return s.biocToSPL2(rule.Name, def)
	case model.RuleTypeIOC:
		return s.iocToSPL2(def)
	case model.RuleTypeUEBA:
		return s.uebaToSPL2(def)
	}
	if def.Source != "" {
		q := fmt.Sprintf(`dataset = %s`, def.Source)
		if def.Condition != "" {
			q += fmt.Sprintf(` | filter %s`, def.Condition)
		}
		return q
	}
	return fmt.Sprintf(`dataset = xsiam_endpoint | filter event_type = "alert"`)
}

func (s *RuleService) biocToSPL2(name string, def model.RuleDefinition) string {
	var parts []string
	for _, event := range def.Sequence {
		conditions := []string{fmt.Sprintf(`event_type = "%s"`, event.EventType)}
		for k, v := range event.Conditions {
			conditions = append(conditions, fmt.Sprintf(`%s = "%s"`, k, v))
		}
		parts = append(parts, "("+strings.Join(conditions, " and ")+")")
	}
	if len(parts) == 0 {
		return fmt.Sprintf(`dataset = xsiam_endpoint | filter rule_name = "%s"`, name)
	}
	return fmt.Sprintf(`dataset = xsiam_endpoint | filter %s`, strings.Join(parts, " or "))
}

func (s *RuleService) iocToSPL2(def model.RuleDefinition) string {
	if len(def.IocValues) == 0 {
		if def.IOCPattern != "" {
			return fmt.Sprintf(`dataset = xsiam_endpoint | filter %s`, def.IOCPattern)
		}
		return `dataset = xsiam_endpoint | filter ioc_match = true`
	}
	values := make([]string, len(def.IocValues))
	for i, v := range def.IocValues {
		values[i] = fmt.Sprintf(`"%s"`, v)
	}
	iocType := def.IocType
	if iocType == "" {
		iocType = "indicator_value"
	}
	return fmt.Sprintf(`dataset = xsiam_endpoint | filter %s in (%s)`, iocType, strings.Join(values, ", "))
}

func (s *RuleService) uebaToSPL2(def model.RuleDefinition) string {
	metric := def.Metric
	if metric == "" {
		metric = "event_count"
	}
	threshold := def.Threshold
	return fmt.Sprintf(`dataset = xsiam_identity | stats count() as %s by user_name | filter %s > %g`, metric, metric, threshold)
}
