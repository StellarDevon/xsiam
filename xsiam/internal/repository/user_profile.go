package repository

import (
	"context"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colUserProfiles = "user_profiles"

type UserProfileRepo struct {
	db arangodb.Database
}

func NewUserProfileRepo(db arangodb.Database) *UserProfileRepo {
	return &UserProfileRepo{db: db}
}

// Get returns the profile for userID, or a default if not found.
func (r *UserProfileRepo) Get(ctx context.Context, userID string) (*model.UserProfile, error) {
	col, err := r.db.Collection(ctx, colUserProfiles)
	if err != nil {
		return nil, err
	}
	var p model.UserProfile
	_, err = col.ReadDocument(ctx, userID, &p)
	if err != nil {
		if shared.IsNotFound(err) {
			return &model.UserProfile{
				Key:    userID,
				UserID: userID,
				Lang:   "zh",
				Theme:  "dark",
			}, nil
		}
		return nil, err
	}
	return &p, nil
}

// Upsert creates or merges the profile document keyed by userID.
func (r *UserProfileRepo) Upsert(ctx context.Context, p *model.UserProfile) error {
	col, err := r.db.Collection(ctx, colUserProfiles)
	if err != nil {
		return err
	}
	p.Key = p.UserID
	p.UpdatedAt = time.Now()

	var existing model.UserProfile
	_, readErr := col.ReadDocument(ctx, p.UserID, &existing)
	if readErr != nil {
		if shared.IsNotFound(readErr) {
			_, err = col.CreateDocument(ctx, p)
			return err
		}
		return readErr
	}

	// Preserve existing values for unset fields.
	if p.DisplayName == "" {
		p.DisplayName = existing.DisplayName
	}
	if p.Email == "" {
		p.Email = existing.Email
	}
	if p.Lang == "" {
		p.Lang = existing.Lang
	}
	if p.Theme == "" {
		p.Theme = existing.Theme
	}
	if p.TenantID == "" {
		p.TenantID = existing.TenantID
	}

	_, err = col.UpdateDocument(ctx, p.UserID, p)
	return err
}
