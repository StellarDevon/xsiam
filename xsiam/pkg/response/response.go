package response

import (
	"net/http"
	"xsiam/internal/model"

	"github.com/gin-gonic/gin"
)

func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": data})
}

func Paginated(c *gin.Context, data any, meta model.PageMeta) {
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": data, "meta": meta}})
}

func BadRequest(c *gin.Context, msg string) {
	c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "BAD_REQUEST", "message": msg}})
}

func Unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "请先登录"}})
}

func Forbidden(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{"success": false, "error": gin.H{"code": "FORBIDDEN", "message": "权限不足"}})
}

func NotFound(c *gin.Context, resource string) {
	c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": resource + " 不存在"}})
}

func InternalError(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "INTERNAL_ERROR", "message": err.Error()}})
}

func Err(c *gin.Context, code int, errCode, msg string) {
	c.JSON(code, gin.H{"success": false, "error": gin.H{"code": errCode, "message": msg}})
}
