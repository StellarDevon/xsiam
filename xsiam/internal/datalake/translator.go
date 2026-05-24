package datalake

import "errors"

// BackendType identifies the analytics backend that stores and queries log data.
type BackendType string

const (
	// NgxBackend — the built-in ngx data lake (SPL2 query language, HEC ingest).
	NgxBackend BackendType = "ngx"

	// ClickHouseBackend — ClickHouse column store (SQL dialect).
	// Reserved for future integration; currently returns ErrNotImplemented.
	ClickHouseBackend BackendType = "clickhouse"

	// StarRocksBackend — StarRocks MPP analytical database (MySQL-compatible SQL).
	// Reserved for future integration; currently returns ErrNotImplemented.
	StarRocksBackend BackendType = "starrocks"
)

// ErrNotImplemented is returned by stub translators that are not yet wired up.
var ErrNotImplemented = errors.New("translator: backend not implemented")

// Translator converts an XSIAM XQL query string to the target backend's
// native query language. Each backend implements its own Translator.
//
// XQL grammar (simplified EBNF):
//
//	query     = "dataset" "=" dataset_name { "|" stage }
//	stage     = filter_stage | fields_stage | sort_stage | limit_stage
//	filter_stage = "filter" condition { "and" condition }
//	condition = field_name "=" quoted_value
//
// The Translator receives the raw XQL string and returns the backend-native
// query. The caller is responsible for supplying time bounds separately.
type Translator interface {
	Translate(xql string) (backendQuery string, err error)
}
