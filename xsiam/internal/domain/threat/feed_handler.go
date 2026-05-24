package threat

import (
	"strconv"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/pkg/response"

	"github.com/gin-gonic/gin"
)

type FeedHandler struct {
	svc *FeedService
}

func NewFeedHandler(svc *FeedService) *FeedHandler {
	return &FeedHandler{svc: svc}
}

func (h *FeedHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), FeedListFilter{
		TenantID: tenantID,
		Keyword:  c.Query("keyword"),
		FeedType: c.Query("feed_type"),
		Status:   c.Query("status"),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *FeedHandler) Get(c *gin.Context) {
	feed, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "intel_feed")
		return
	}
	response.OK(c, feed)
}

func (h *FeedHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var feed model.IntelFeed
	if err := c.ShouldBindJSON(&feed); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	feed.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &feed, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, feed)
}

func (h *FeedHandler) Update(c *gin.Context) {
	key := c.Param("id")
	var patch map[string]any
	if err := c.ShouldBindJSON(&patch); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Update(c.Request.Context(), key, patch); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"_key": key})
}

func (h *FeedHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *FeedHandler) Sync(c *gin.Context) {
	key := c.Param("id")
	operatorID := c.GetString(middleware.CtxUserID)
	jobID, err := h.svc.Sync(c.Request.Context(), key, operatorID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"job_id": jobID})
}

// BulkSync triggers sync for multiple intel feeds.
// POST /api/intel_feeds/bulk_sync
func (h *FeedHandler) BulkSync(c *gin.Context) {
	var body struct {
		Keys []string `json:"keys"`
		IDs  []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	operatorID := c.GetString(middleware.CtxUserID)
	synced := 0
	for _, k := range keys {
		if _, err := h.svc.Sync(c.Request.Context(), k, operatorID); err == nil {
			synced++
		}
	}
	c.JSON(200, gin.H{"synced": synced})
}
