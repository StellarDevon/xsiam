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
	spl2 := c.Query("spl2")
	if spl2 == "" {
		response.BadRequest(c, "spl2 query is required")
		return
	}
	fromTS, _ := strconv.ParseInt(c.DefaultQuery("from_ts", "0"), 10, 64)
	toTS, _ := strconv.ParseInt(c.DefaultQuery("to_ts", "0"), 10, 64)
	result, err := h.svc.Query(c.Request.Context(), spl2, fromTS, toTS)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *Handler) Datasets(c *gin.Context) {
	response.OK(c, h.svc.Datasets(c.Request.Context()))
}
