package identity

import (
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type PrivilegeHandler struct {
	repo *repository.PrivilegeRestrictionRepo
}

func NewPrivilegeHandler(repo *repository.PrivilegeRestrictionRepo) *PrivilegeHandler {
	return &PrivilegeHandler{repo: repo}
}

// List GET /privilege_restrictions
// Returns active restrictions for the caller's tenant.
// Optional query param: user_id — when present, filters to that specific user.
func (h *PrivilegeHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	userID := c.Query("user_id")
	items, err := h.repo.List(c.Request.Context(), tenantID, userID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"items": items})
}

// Create POST /privilege_restrictions
// Accepts JSON body:
//
//	{ "user_id": "user123", "reason": "anomalous login",
//	  "restrictions": ["disable_login","revoke_sessions"],
//	  "expires_at": "2026-06-01T00:00:00Z" }
func (h *PrivilegeHandler) Create(c *gin.Context) {
	var pr model.PrivilegeRestriction
	if err := c.ShouldBindJSON(&pr); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	pr.TenantID = c.GetString(middleware.CtxTenantID)
	if err := h.repo.Create(c.Request.Context(), &pr); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, pr)
}

// Release PUT /privilege_restrictions/release
// Accepts JSON body: { "user_id": "user123" }
// Deactivates all active restrictions for that user within the caller's tenant.
func (h *PrivilegeHandler) Release(c *gin.Context) {
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.UserID == "" {
		response.BadRequest(c, "user_id is required")
		return
	}
	tenantID := c.GetString(middleware.CtxTenantID)
	if err := h.repo.ReleaseByUserID(c.Request.Context(), body.UserID, tenantID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"released": body.UserID})
}

// Delete DELETE /privilege_restrictions/:id
// Permanently removes a privilege restriction document by its _key.
func (h *PrivilegeHandler) Delete(c *gin.Context) {
	key := c.Param("id")
	if key == "" {
		response.BadRequest(c, "id is required")
		return
	}
	if err := h.repo.Delete(c.Request.Context(), key); err != nil {
		response.NotFound(c, "privilege_restriction")
		return
	}
	response.OK(c, gin.H{"_key": key})
}

// Stats GET /privilege_restrictions/stats
// Returns the count of currently active privilege restrictions for the caller's tenant.
func (h *PrivilegeHandler) Stats(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	count, err := h.repo.CountActive(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"active_count": count})
}
