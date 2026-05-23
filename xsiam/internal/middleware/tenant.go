package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// TenantContext reads the tenant_id previously set by JWTAuth and re-exposes
// it as a typed string. Must be applied after JWTAuth.
func TenantContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		tid := c.GetString(CtxTenantID)
		if tid == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "tenant not resolved"})
			return
		}
		c.Next()
	}
}

// RequireSuperTenant aborts the request if the caller is not a super-tenant.
func RequireSuperTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString(CtxRole)
		if role != "super_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "super tenant required"})
			return
		}
		c.Next()
	}
}
