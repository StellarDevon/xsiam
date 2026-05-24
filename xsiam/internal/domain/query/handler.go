package query

import (
	"strconv"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Query(c *gin.Context) {
	// Accept both "q" (frontend convention) and "spl2" (legacy).
	xql := c.Query("q")
	if xql == "" {
		xql = c.Query("spl2")
	}
	if xql == "" {
		response.BadRequest(c, "query parameter 'q' is required")
		return
	}
	fromTS, _ := strconv.ParseInt(c.DefaultQuery("from_ts", "0"), 10, 64)
	toTS, _ := strconv.ParseInt(c.DefaultQuery("to_ts", "0"), 10, 64)

	// Inject tenant_id from gin context into request context so the service
	// can scope its AQL query.
	ctx := c.Request.Context()
	if tid, ok := c.Get("tenant_id"); ok {
		ctx = contextWithTenant(ctx, tid.(string))
	}

	result, err := h.svc.Query(ctx, xql, fromTS, toTS)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, result)
}

func (h *Handler) Datasets(c *gin.Context) {
	response.OK(c, h.svc.Datasets(c.Request.Context()))
}
