package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"xsiam/pkg/svcclient"
)

// RequirePermission checks that the authenticated user has the given permission
// (format: "resource:action"). Works with both HTTP and in-process callers.
func RequirePermission(svc svcclient.Caller, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString(CtxUserID)
		tenantID := c.GetString(CtxTenantID)

		allowed, err := svc.CheckPermission(c.Request.Context(), userID, tenantID, resource, action)
		if err != nil || !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    403,
				"message": "permission denied: " + resource + ":" + action,
			})
			return
		}
		c.Next()
	}
}
