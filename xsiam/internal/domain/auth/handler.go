package auth

import (
	"net/http"
	"strconv"
	"time"
	"xsiam/internal/middleware"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/response"

	alertdomain "xsiam/internal/domain/alert"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	authSvc *AuthService
}

func NewHandler(svc *AuthService) *Handler {
	return &Handler{authSvc: svc}
}

func (h *Handler) Login(c *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	resp, err := h.authSvc.Login(c.Request.Context(), body.Email, body.Password)
	if err != nil {
		response.Err(c, 401, "INVALID_CREDENTIALS", err.Error())
		return
	}
	response.OK(c, resp)
}

type UserHandler struct {
	svc         *UserService
	profileRepo *repository.UserProfileRepo
}

func NewUserHandler(svc *UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

func NewUserHandlerWithProfile(svc *UserService, profileRepo *repository.UserProfileRepo) *UserHandler {
	return &UserHandler{svc: svc, profileRepo: profileRepo}
}

func (h *UserHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	for i := range data {
		data[i].PasswordHash = ""
	}
	response.Paginated(c, data, meta)
}

func (h *UserHandler) Get(c *gin.Context) {
	user, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "user")
		return
	}
	user.PasswordHash = ""
	response.OK(c, user)
}

func (h *UserHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var user model.User
	if err := c.ShouldBindJSON(&user); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	user.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &user, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	user.PasswordHash = ""
	response.Created(c, user)
}

func (h *UserHandler) Update(c *gin.Context) {
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

func (h *UserHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	key := c.Param("id")
	var body struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.ChangePassword(c.Request.Context(), key, body.OldPassword, body.NewPassword); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.OK(c, gin.H{"message": "password changed"})
}

// Me returns the profile of the currently authenticated user.
// GET /api/users/me
func (h *UserHandler) Me(c *gin.Context) {
	userID := c.GetString(middleware.CtxUserID)
	if userID == "" {
		response.Unauthorized(c)
		return
	}
	user, err := h.svc.Get(c.Request.Context(), userID)
	if err != nil {
		// Fallback: return basic JWT-derived info
		c.JSON(200, gin.H{
			"_key":      userID,
			"user_id":   userID,
			"role":      c.GetString(middleware.CtxRole),
			"tenant_id": c.GetString(middleware.CtxTenantID),
		})
		return
	}
	user.PasswordHash = ""
	response.OK(c, user)
}

// Bulk performs bulk enable/disable on users.
// POST /api/users/bulk
func (h *UserHandler) Bulk(c *gin.Context) {
	var body struct {
		Action string   `json:"action" binding:"required"`
		Keys   []string `json:"keys"`
		IDs    []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	keys := body.Keys
	if len(keys) == 0 {
		keys = body.IDs
	}
	if len(keys) == 0 {
		response.BadRequest(c, "keys or ids required")
		return
	}
	var patch map[string]any
	switch body.Action {
	case "enable":
		patch = map[string]any{"enabled": true}
	case "disable":
		patch = map[string]any{"enabled": false}
	default:
		response.BadRequest(c, "unknown action: "+body.Action)
		return
	}
	count := 0
	for _, k := range keys {
		if err := h.svc.Update(c.Request.Context(), k, patch); err == nil {
			count++
		}
	}
	response.OK(c, gin.H{"updated": count})
}

// GetProfile returns the current user's profile (lang, theme, display_name, email).
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetString(middleware.CtxUserID)
	if userID == "" || h.profileRepo == nil {
		response.OK(c, model.UserProfile{Lang: "zh", Theme: "dark"})
		return
	}
	p, err := h.profileRepo.Get(c.Request.Context(), userID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, p)
}

// UpdateProfile saves the current user's profile preferences.
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetString(middleware.CtxUserID)
	tenantID := c.GetString(middleware.CtxTenantID)
	if userID == "" || h.profileRepo == nil {
		response.OK(c, gin.H{"ok": true})
		return
	}
	var body struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Lang        string `json:"lang"`
		Theme       string `json:"theme"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	p := &model.UserProfile{
		UserID:      userID,
		TenantID:    tenantID,
		DisplayName: body.DisplayName,
		Email:       body.Email,
		Lang:        body.Lang,
		Theme:       body.Theme,
	}
	if err := h.profileRepo.Upsert(c.Request.Context(), p); err != nil {
		response.InternalError(c, err)
		return
	}
	// If display_name or email changed, also patch the user record.
	patch := map[string]any{}
	if body.DisplayName != "" {
		patch["display_name"] = body.DisplayName
	}
	if body.Email != "" {
		patch["email"] = body.Email
	}
	if len(patch) > 0 {
		_ = h.svc.Update(c.Request.Context(), userID, patch)
	}
	response.OK(c, p)
}

type TenantHandler struct {
	svc *TenantService
}

func NewTenantHandler(svc *TenantService) *TenantHandler {
	return &TenantHandler{svc: svc}
}

func (h *TenantHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	data, meta, err := h.svc.List(c.Request.Context(), page, pageSize)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.Paginated(c, data, meta)
}

func (h *TenantHandler) Get(c *gin.Context) {
	tenant, err := h.svc.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		response.NotFound(c, "tenant")
		return
	}
	response.OK(c, tenant)
}

func (h *TenantHandler) Create(c *gin.Context) {
	operatorID := c.GetString(middleware.CtxUserID)
	var tenant model.Tenant
	if err := c.ShouldBindJSON(&tenant); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.Create(c.Request.Context(), &tenant, operatorID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.Created(c, tenant)
}

func (h *TenantHandler) Update(c *gin.Context) {
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

func (h *TenantHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

type RBACHandler struct {
	svc *RBACService
}

func NewRBACHandler(svc *RBACService) *RBACHandler {
	return &RBACHandler{svc: svc}
}

func (h *RBACHandler) List(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	data, err := h.svc.List(c.Request.Context(), tenantID)
	if err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, data)
}

func (h *RBACHandler) Create(c *gin.Context) {
	tenantID := c.GetString(middleware.CtxTenantID)
	operatorID := c.GetString(middleware.CtxUserID)
	var role model.RBACRole
	if err := c.ShouldBindJSON(&role); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	role.TenantID = tenantID
	if err := h.svc.Create(c.Request.Context(), &role, operatorID); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Created(c, role)
}

func (h *RBACHandler) Update(c *gin.Context) {
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

func (h *RBACHandler) Delete(c *gin.Context) {
	if err := h.svc.Delete(c.Request.Context(), c.Param("id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

func (h *RBACHandler) AddMember(c *gin.Context) {
	roleKey := c.Param("id")
	var body struct {
		UserID string `json:"user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.svc.AddMember(c.Request.Context(), roleKey, body.UserID); err != nil {
		response.InternalError(c, err)
		return
	}
	response.OK(c, gin.H{"role_key": roleKey, "user_id": body.UserID})
}

func (h *RBACHandler) RemoveMember(c *gin.Context) {
	if err := h.svc.RemoveMember(c.Request.Context(), c.Param("id"), c.Param("user_id")); err != nil {
		response.InternalError(c, err)
		return
	}
	c.Status(204)
}

// InternalHandler processes inbound webhooks from the datalake on the internal port.
type InternalHandler struct {
	alertSvc *alertdomain.Service
}

func NewInternalHandler(alertSvc *alertdomain.Service) *InternalHandler {
	return &InternalHandler{alertSvc: alertSvc}
}

type ngxWebhookPayload struct {
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    string         `json:"severity"`
	ResultCount uint64         `json:"result_count"`
	SourceType  string         `json:"source_type"`
	AssetID     *string        `json:"asset_id"`
	AssetName   string         `json:"asset_name"`
	UserName    *string        `json:"user_name"`
	Tactics     []string       `json:"mitre_tactics"`
	Techniques  []string       `json:"mitre_techniques"`
	TenantID    string         `json:"tenant_id"`
	RawData     map[string]any `json:"raw_data"`
}

func (h *InternalHandler) CreateFromRule(c *gin.Context) {
	var payload ngxWebhookPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	severity := model.Severity(payload.Severity)
	if severity == "" {
		severity = model.SeverityMedium
	}
	sourceType := model.SourceType(payload.SourceType)
	if sourceType == "" {
		sourceType = model.SourceEndpoint
	}
	req := alertdomain.CreateAlertReq{
		Name:            payload.RuleName,
		Description:     "Triggered by ngx rule: " + payload.RuleID,
		Severity:        severity,
		SourceType:      sourceType,
		TenantID:        payload.TenantID,
		AssetID:         payload.AssetID,
		AssetName:       payload.AssetName,
		TriggerSource:   "ngx_saved_search",
		ResultCount:     payload.ResultCount,
		MitreTactics:    payload.Tactics,
		MitreTechniques: payload.Techniques,
		RuleID:          payload.RuleID,
		RuleName:        payload.RuleName,
	}
	alert, err := h.alertSvc.Create(c.Request.Context(), req, "system")
	if err != nil {
		response.InternalError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"alert_key":  alert.Key,
		"alert_id":   alert.AlertID,
		"created_at": time.Now(),
	})
}
