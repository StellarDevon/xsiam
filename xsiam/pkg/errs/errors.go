package errs

import "errors"

var (
	ErrNotFound         = errors.New("not found")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrBadRequest       = errors.New("bad request")
	ErrConflict         = errors.New("conflict")
	ErrInvalidTransition = errors.New("invalid status transition")
)

const (
	CodeNotFound     = "NOT_FOUND"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeForbidden    = "FORBIDDEN"
	CodeBadRequest   = "BAD_REQUEST"
	CodeConflict     = "CONFLICT"
	CodeInternal     = "INTERNAL_ERROR"
)
