package threat

import (
	"context"
	"xsiam/internal/model"
)

type FeedService struct {
	feedRepo   *FeedRepo
	feedPuller *FeedPuller
	auditRepo  AuditLogger
}

func NewFeedService(feedRepo *FeedRepo, feedPuller *FeedPuller, auditRepo AuditLogger) *FeedService {
	return &FeedService{feedRepo: feedRepo, feedPuller: feedPuller, auditRepo: auditRepo}
}

func (s *FeedService) List(ctx context.Context, f FeedListFilter) ([]model.IntelFeed, model.PageMeta, error) {
	return s.feedRepo.List(ctx, f)
}

func (s *FeedService) Get(ctx context.Context, key string) (*model.IntelFeed, error) {
	return s.feedRepo.GetByID(ctx, key)
}

func (s *FeedService) Create(ctx context.Context, feed *model.IntelFeed, operatorID string) error {
	return s.feedRepo.Create(ctx, feed)
}

func (s *FeedService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.feedRepo.Update(ctx, key, patch)
}

func (s *FeedService) Delete(ctx context.Context, key string) error {
	return s.feedRepo.Delete(ctx, key)
}

func (s *FeedService) Sync(ctx context.Context, key, operatorID string) (string, error) {
	feed, err := s.feedRepo.GetByID(ctx, key)
	if err != nil {
		return "", err
	}
	return s.feedPuller.TriggerFeedSync(ctx, feed.Key)
}
