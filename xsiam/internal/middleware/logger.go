package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Logger returns a gin middleware that logs each request using zap.
func Logger(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		fields := []zap.Field{
			zap.Int("status", status),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.Duration("latency", latency),
		}

		if len(c.Errors) > 0 {
			for _, e := range c.Errors {
				log.Error("request error", append(fields, zap.Error(e.Err))...)
			}
		} else {
			if status >= 500 {
				log.Error("server error", fields...)
			} else if status >= 400 {
				log.Warn("client error", fields...)
			} else {
				log.Info("request", fields...)
			}
		}
	}
}
