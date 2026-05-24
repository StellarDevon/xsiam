package datalake

import (
	"context"
	"fmt"
)

// Router wraps a QueryClient and a Translator to form a backend-agnostic
// query interface.  It satisfies QueryClient itself, so it can be passed
// anywhere a QueryClient is expected without any change to callers.
//
// On each Query call the Router:
//  1. Calls Translator.Translate(xql) to produce the backend-native query string.
//  2. Delegates to the wrapped client with the translated query.
//
// Current backend support:
//
//	ngx        — fully implemented (XQL → SPL2 via NgxTranslator)
//	clickhouse — stub (returns ErrNotImplemented)
//	starrocks  — stub (returns ErrNotImplemented)
type Router struct {
	backend    BackendType
	translator Translator
	client     QueryClient
}

// NewRouter constructs a Router for the given backend.
// client is the underlying QueryClient (e.g. *datalake.Client for NgxBackend).
// For stub backends (ClickHouse, StarRocks) client is not called, so nil is acceptable.
func NewRouter(backend BackendType, client QueryClient) (*Router, error) {
	var t Translator
	switch backend {
	case NgxBackend, "": // default to ngx
		t = NewNgxTranslator()
	case ClickHouseBackend:
		t = &ClickHouseTranslator{}
	case StarRocksBackend:
		t = &StarRocksTranslator{}
	default:
		return nil, fmt.Errorf("datalake router: unknown backend %q (valid: ngx, clickhouse, starrocks)", backend)
	}
	return &Router{backend: backend, translator: t, client: client}, nil
}

// Backend returns the configured backend type.
func (r *Router) Backend() BackendType { return r.backend }

// Query implements QueryClient.
// It translates the XQL query to the backend's native language, then
// delegates to the wrapped client.
func (r *Router) Query(ctx context.Context, xql string, fromTS, toTS int64) (*QueryResult, error) {
	backendQ, err := r.translator.Translate(xql)
	if err != nil {
		return nil, fmt.Errorf("datalake router translate [%s]: %w", r.backend, err)
	}
	if r.client == nil {
		return nil, fmt.Errorf("datalake router: no client configured for backend %q", r.backend)
	}
	return r.client.Query(ctx, backendQ, fromTS, toTS)
}
