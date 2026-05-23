package repository

func InjectTenantFilter(filters []string, bindVars map[string]any, tenantID string) ([]string, map[string]any) {
	if tenantID == "" {
		return filters, bindVars
	}
	filters = append(filters, "doc.tenant_id == @tenantID")
	bindVars["tenantID"] = tenantID
	return filters, bindVars
}
