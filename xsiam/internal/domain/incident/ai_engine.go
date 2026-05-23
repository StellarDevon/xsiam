package incident

type ScoreFactor struct {
	Name   string  `json:"name"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

type SmartScoreResult struct {
	Score   float64       `json:"score"`
	Factors []ScoreFactor `json:"factors"`
}

type AIEngine struct{ enabled bool }

func NewAIEngine(enabled bool) *AIEngine { return &AIEngine{enabled: enabled} }

func (s *AIEngine) CalcSmartScore(flags map[string]bool) SmartScoreResult {
	var score float64
	var factors []ScoreFactor
	weights := map[string]struct {
		Name string
		W    float64
	}{
		"critical_asset":   {"关键资产受影响", 35},
		"lateral_movement": {"横向移动检测", 28},
		"exfiltration":     {"数据外泄行为", 22},
		"c2_communication": {"外部 C2 通信", 13},
	}
	for key, w := range weights {
		if flags[key] {
			score += w.W
			factors = append(factors, ScoreFactor{Name: w.Name, Score: w.W, Weight: w.W / 100})
		}
	}
	if score > 100 {
		score = 100
	}
	return SmartScoreResult{Score: score, Factors: factors}
}
