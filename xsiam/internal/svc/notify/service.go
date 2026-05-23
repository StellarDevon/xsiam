package notify

import (
	"context"
	"fmt"
	"xsiam/config"
)

// Notification represents a message to be sent.
type Notification struct {
	Channel  string   `json:"channel"` // email | dingtalk | slack | sms
	To       []string `json:"to"`
	Subject  string   `json:"subject"`
	Body     string   `json:"body"`
	Markdown bool     `json:"markdown"`
}

// Sender is the interface each channel adapter must implement.
type Sender interface {
	Send(ctx context.Context, n Notification) error
}

// Service dispatches notifications to channel-specific adapters.
type Service struct {
	adapters map[string]Sender
}

func New(cfg config.NotifyConfig) *Service {
	s := &Service{adapters: make(map[string]Sender)}
	if cfg.Email.Enabled {
		s.adapters["email"] = NewEmailSender(cfg.Email)
	}
	if cfg.DingTalk.Enabled {
		s.adapters["dingtalk"] = NewDingTalkSender(cfg.DingTalk)
	}
	if cfg.Slack.Enabled {
		s.adapters["slack"] = NewSlackSender(cfg.Slack)
	}
	return s
}

// Send routes the notification to the correct adapter.
func (s *Service) Send(ctx context.Context, n Notification) error {
	adapter, ok := s.adapters[n.Channel]
	if !ok {
		return fmt.Errorf("notify: no adapter for channel %q", n.Channel)
	}
	return adapter.Send(ctx, n)
}
