package utils

import (
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.New(rand.NewSource(time.Now().UnixNano()))
}

func newID(prefix string) string {
	return fmt.Sprintf("%s-%d-%06d", prefix, time.Now().UnixMilli(), rand.Intn(1000000))
}

func NewAlertID() string    { return newID("ALT") }
func NewIncidentID() string { return newID("INC") }
func NewGraphID() string    { return newID("GRP") }
func NewRuleID() string     { return newID("RUL") }
func NewTenantID() string   { return newID("TEN") }
func NewRoleID() string     { return newID("ROL") }
func NewNodeID() string     { return newID("NOD") }

// GenerateAlertID is an alias for NewAlertID for backward compat.
func GenerateAlertID() string { return NewAlertID() }

// GenerateGraphID is an alias for NewGraphID.
func GenerateGraphID() string { return NewGraphID() }
