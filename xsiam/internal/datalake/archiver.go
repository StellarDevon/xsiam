package datalake

import (
	"context"
	"encoding/json"
	"time"
	"xsiam/internal/repository"

	"go.uber.org/zap"
)

type Archiver struct {
	alertRepo *repository.AlertRepo
	lake      *Client
	log       *zap.Logger
}

func NewArchiver(alertRepo *repository.AlertRepo, lake *Client) *Archiver {
	return &Archiver{alertRepo: alertRepo, lake: lake, log: zap.L()}
}

const alertArchiveDays = 30

func (a *Archiver) ArchiveAlerts(ctx context.Context) error {
	cutoff := time.Now().AddDate(0, 0, -alertArchiveDays+2)
	oldest := time.Now().AddDate(0, 0, -alertArchiveDays)

	alerts, err := a.alertRepo.FindByTimeRange(ctx, oldest, cutoff)
	if err != nil {
		a.log.Error("archive query failed", zap.Error(err))
		return err
	}
	if len(alerts) == 0 {
		return nil
	}

	batch := make([]HECEvent, 0, len(alerts))
	for _, al := range alerts {
		raw := alertToMap(al)
		batch = append(batch, HECEvent{
			Time:       al.TriggeredAt.Unix(),
			Index:      "xsiam_alerts_archive",
			Sourcetype: "xsiam:alert:archived",
			Event:      raw,
		})
		if len(batch) >= 100 {
			_ = a.lake.Ingest(ctx, batch)
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		_ = a.lake.Ingest(ctx, batch)
	}
	a.log.Info("archived alerts to ngx", zap.Int("count", len(alerts)))
	return nil
}

func alertToMap(a any) map[string]any {
	b, _ := json.Marshal(a)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}
