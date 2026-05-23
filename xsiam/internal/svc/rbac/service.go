package rbac

import (
	"context"
	"strings"
	"xsiam/internal/repository"
)

// Service checks whether a user has a specific permission via AQL.
type Service struct {
	roleRepo *repository.RBACRoleRepo
}

func New(roleRepo *repository.RBACRoleRepo) *Service {
	return &Service{roleRepo: roleRepo}
}

// Check returns true if the user has the given permission in the tenant.
// Permission format: "resource:action".
func (s *Service) Check(ctx context.Context, userID, tenantID, permission string) (bool, error) {
	roles, err := s.roleRepo.List(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		isMember := false
		for _, m := range role.Members {
			if m == userID {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}
		for _, p := range role.Permissions {
			if p == permission || p == "*" || matchWildcard(p, permission) {
				return true, nil
			}
		}
	}
	return false, nil
}

// matchWildcard supports "resource:*" and "*:action" patterns.
func matchWildcard(pattern, permission string) bool {
	pp := strings.SplitN(pattern, ":", 2)
	perm := strings.SplitN(permission, ":", 2)
	if len(pp) != 2 || len(perm) != 2 {
		return false
	}
	resourceMatch := pp[0] == "*" || pp[0] == perm[0]
	actionMatch := pp[1] == "*" || pp[1] == perm[1]
	return resourceMatch && actionMatch
}
