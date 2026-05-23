package notify

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"xsiam/config"
)

// EmailSender sends notifications via SMTP.
type EmailSender struct {
	cfg config.EmailConfig
}

func NewEmailSender(cfg config.EmailConfig) *EmailSender {
	return &EmailSender{cfg: cfg}
}

func (s *EmailSender) Send(_ context.Context, n Notification) error {
	auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		s.cfg.From,
		strings.Join(n.To, ", "),
		n.Subject,
		n.Body,
	)

	return smtp.SendMail(addr, auth, s.cfg.From, n.To, []byte(msg))
}
