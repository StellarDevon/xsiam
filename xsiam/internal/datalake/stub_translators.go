package datalake

// ClickHouseTranslator is a placeholder for future ClickHouse SQL translation.
//
// ClickHouse uses a SQL dialect with some extensions:
//   - Time filtering:  WHERE toDateTime(event_timestamp) BETWEEN ... AND ...
//   - Dataset mapping: SELECT ... FROM <dataset>
//   - The full implementation should use a proper AST rewriter, not string
//     manipulation, to handle nested conditions and aggregations correctly.
//
// To implement: replace this stub with a real ClickHouseTranslator that
// converts xqlParsed into a ClickHouse SQL SELECT statement and uses the
// ClickHouse HTTP interface (POST /query or native TCP driver).
type ClickHouseTranslator struct {
	// DSN string — ClickHouse HTTP endpoint, e.g. "http://localhost:8123"
	DSN string
}

// Translate returns ErrNotImplemented until the ClickHouse backend is wired up.
func (t *ClickHouseTranslator) Translate(_ string) (string, error) {
	return "", ErrNotImplemented
}

// StarRocksTranslator is a placeholder for future StarRocks SQL translation.
//
// StarRocks is MySQL-protocol compatible. Translation follows the same pattern
// as ClickHouseTranslator but targets StarRocks SQL syntax:
//   - Dataset mapping: SELECT ... FROM <catalog>.<database>.<dataset>
//   - Time filtering:  WHERE event_timestamp BETWEEN FROM_UNIXTIME(?) AND FROM_UNIXTIME(?)
//   - Use mysql driver (github.com/go-sql-driver/mysql) or StarRocks HTTP connector.
//
// To implement: replace this stub with a real StarRocksTranslator.
type StarRocksTranslator struct {
	// DSN string — StarRocks MySQL-compatible endpoint, e.g. "user:pass@tcp(host:9030)/"
	DSN string
}

// Translate returns ErrNotImplemented until the StarRocks backend is wired up.
func (t *StarRocksTranslator) Translate(_ string) (string, error) {
	return "", ErrNotImplemented
}
