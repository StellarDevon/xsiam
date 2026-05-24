package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"xsiam/internal/domain/alert"
	"xsiam/internal/domain/incident"
	"xsiam/internal/domain/threat"
	"xsiam/internal/repository"
)

const anthropicAPI = "https://api.anthropic.com/v1/messages"
const defaultModel = "claude-sonnet-4-6"

// Service is the AI Copilot service that calls the Anthropic Claude API
// with live XSIAM platform data injected as context.
type Service struct {
	apiKey       string
	alertRepo    *alert.Repo
	incidentRepo *incident.Repo
	iocRepo      *threat.IocRepo
}

func NewService(apiKey string, alertRepo *alert.Repo, incidentRepo *incident.Repo, iocRepo *threat.IocRepo) *Service {
	return &Service{
		apiKey:       apiKey,
		alertRepo:    alertRepo,
		incidentRepo: incidentRepo,
		iocRepo:      iocRepo,
	}
}

type ChatRequest struct {
	Message  string `json:"message"`
	TenantID string `json:"-"`
}

type ChatResponse struct {
	Reply     string `json:"reply"`
	TokensIn  int    `json:"tokens_in,omitempty"`
	TokensOut int    `json:"tokens_out,omitempty"`
	Model     string `json:"model"`
}

// buildContext gathers live security data to inject into the system prompt.
func (s *Service) buildContext(ctx context.Context, tenantID string) string {
	var sb bytes.Buffer
	sb.WriteString("=== LIVE XSIAM PLATFORM DATA ===\n")
	sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))

	// Active alerts
	alerts, _, err := s.alertRepo.List(ctx, repository.AlertListFilter{
		TenantID: tenantID, Page: 1, PageSize: 200,
	})
	if err == nil {
		critCount, highCount, medCount := 0, 0, 0
		activeCount := 0
		for _, a := range alerts {
			if a.Status == "active" || a.Status == "investigating" {
				activeCount++
			}
			switch string(a.Severity) {
			case "critical":
				critCount++
			case "high":
				highCount++
			case "medium":
				medCount++
			}
		}
		sb.WriteString(fmt.Sprintf("ALERTS: total=%d active=%d [critical=%d high=%d medium=%d]\n",
			len(alerts), activeCount, critCount, highCount, medCount))
		sb.WriteString("Recent alerts:\n")
		limit := 5
		if len(alerts) < limit {
			limit = len(alerts)
		}
		for _, a := range alerts[:limit] {
			sb.WriteString(fmt.Sprintf("  - [%s] %s (host=%s status=%s)\n",
				string(a.Severity), a.Name, a.Host, string(a.Status)))
		}
		sb.WriteString("\n")
	}

	// Active incidents
	incidents, _, err := s.incidentRepo.List(ctx, repository.IncidentListFilter{
		TenantID: tenantID, Page: 1, PageSize: 50,
	})
	if err == nil {
		openCount := 0
		for _, inc := range incidents {
			if inc.Status != "closed" && inc.Status != "resolved" {
				openCount++
			}
		}
		sb.WriteString(fmt.Sprintf("INCIDENTS: total=%d open=%d\n", len(incidents), openCount))
		sb.WriteString("Recent incidents:\n")
		limit := 5
		if len(incidents) < limit {
			limit = len(incidents)
		}
		for _, inc := range incidents[:limit] {
			sb.WriteString(fmt.Sprintf("  - [%s] %s (status=%s smartscore=%.0f)\n",
				string(inc.Severity), inc.Name, string(inc.Status), inc.SmartScore))
		}
		sb.WriteString("\n")
	}

	// Active IOCs
	iocs, _, err := s.iocRepo.List(ctx, repository.IocListFilter{
		TenantID: tenantID, Page: 1, PageSize: 20, Verdict: "malicious",
	})
	if err == nil {
		sb.WriteString(fmt.Sprintf("ACTIVE MALICIOUS IOCs: %d\n", len(iocs)))
		limit := 5
		if len(iocs) < limit {
			limit = len(iocs)
		}
		for _, ioc := range iocs[:limit] {
			sb.WriteString(fmt.Sprintf("  - [%s] %s (%s confidence=%.0f%%)\n",
				string(ioc.Type), ioc.Value, ioc.ThreatName, ioc.Confidence))
		}
	}

	return sb.String()
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Model string `json:"model"`
}

func (s *Service) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if s.apiKey == "" {
		// Fallback stub when no API key configured
		return &ChatResponse{
			Reply: fmt.Sprintf("[AI Copilot - Demo Mode] Query received: %q\n\nTo enable real AI responses, set ANTHROPIC_API_KEY in your environment or config.yaml.", req.Message),
			Model: "stub",
		}, nil
	}

	liveCtx := s.buildContext(ctx, req.TenantID)

	systemPrompt := fmt.Sprintf(`You are XSIAM Copilot, an AI security operations assistant integrated into the XSIAM platform.
You help SOC analysts investigate security incidents, understand threat patterns, and make decisions.

Your capabilities:
- Analyze and explain security alerts and incidents
- Identify patterns in threat data
- Suggest investigation steps and remediation actions
- Translate natural language into XQL queries (dataset=xdr_data | filter ...)
- Summarize security posture and risk

Guidelines:
- Be concise and actionable
- Use security terminology appropriately
- When suggesting XQL queries, wrap them in code blocks
- For critical threats, clearly flag urgency
- Reference specific data points from the live context below

%s`, liveCtx)

	body := anthropicRequest{
		Model:     defaultModel,
		MaxTokens: 1024,
		System:    systemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: req.Message}},
	}

	bodyBytes, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPI, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("copilot: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", s.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("copilot: anthropic request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("copilot: anthropic error %d: %s", resp.StatusCode, string(respBytes))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respBytes, &ar); err != nil {
		return nil, fmt.Errorf("copilot: parse response: %w", err)
	}

	reply := ""
	for _, c := range ar.Content {
		if c.Type == "text" {
			reply += c.Text
		}
	}

	return &ChatResponse{
		Reply:     reply,
		TokensIn:  ar.Usage.InputTokens,
		TokensOut: ar.Usage.OutputTokens,
		Model:     ar.Model,
	}, nil
}

// NL2XQL converts a natural language query to XQL via the AI engine.
// If no API key is configured it returns a stub XQL comment.
func (s *Service) NL2XQL(ctx context.Context, nlQuery string) (string, error) {
	if s.apiKey == "" {
		stub := "dataset = xdr_data | filter /* natural language: " + nlQuery + " */"
		return stub, nil
	}

	systemPrompt := "You are an XQL query generator for the XSIAM security platform. " +
		"Convert the following natural language query to XQL. " +
		"Return ONLY the XQL query, no explanation:\n" + nlQuery

	body := anthropicRequest{
		Model:     defaultModel,
		MaxTokens: 512,
		System:    systemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: nlQuery}},
	}

	bodyBytes, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPI, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("nl2xql: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", s.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("nl2xql: anthropic request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nl2xql: anthropic error %d: %s", resp.StatusCode, string(respBytes))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(respBytes, &ar); err != nil {
		return "", fmt.Errorf("nl2xql: parse response: %w", err)
	}

	xql := ""
	for _, c := range ar.Content {
		if c.Type == "text" {
			xql += c.Text
		}
	}

	// Strip markdown code fences if present.
	xql = strings.TrimSpace(xql)
	if strings.HasPrefix(xql, "```") {
		lines := strings.Split(xql, "\n")
		if len(lines) >= 2 {
			// Drop opening fence (first line) and closing fence (last line if it is "```")
			inner := lines[1:]
			if len(inner) > 0 && strings.TrimSpace(inner[len(inner)-1]) == "```" {
				inner = inner[:len(inner)-1]
			}
			xql = strings.TrimSpace(strings.Join(inner, "\n"))
		}
	}

	return xql, nil
}
