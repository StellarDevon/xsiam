package threat

import (
	"context"
	"fmt"
	"time"
)

// FeedPuller triggers remote intel feed synchronization jobs.
type FeedPuller struct{ enabled bool }

func NewFeedPuller(enabled bool) *FeedPuller { return &FeedPuller{enabled: enabled} }

func (p *FeedPuller) TriggerFeedSync(_ context.Context, _ string) (string, error) {
	return fmt.Sprintf("JOB-%d", time.Now().UnixMilli()), nil
}
