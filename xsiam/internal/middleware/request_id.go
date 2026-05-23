package middleware

import (
	requestid "github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
)

// RequestID injects a unique X-Request-ID into each request context.
func RequestID() gin.HandlerFunc {
	return requestid.New()
}
