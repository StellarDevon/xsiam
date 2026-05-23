package domain

// FirstOf returns the first non-empty string from the provided values.
// Used to support both "q" and "keyword" query param aliases.
func FirstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
