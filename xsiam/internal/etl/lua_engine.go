// Package etl — Lua custom processing rule engine.
//
// Each call to LuaEngine.Run creates a fresh, isolated LuaState so that
// scripts cannot leak state between events or between tenants.
//
// # Lua function contract (Fluent Bit compatible)
//
//	function process(tag, timestamp_ms, record)
//	    -- tag          : string  — XLOG tag (e.g. "winevent.security")
//	    -- timestamp_ms : number  — event timestamp in milliseconds since epoch
//	    -- record       : table   — all entry fields as a flat key→value table
//	    --                          top-level entry fields (hostname, src_ip, …)
//	    --                          are merged in alongside Fields map entries.
//
//	    -- return codes:
//	    --   1  → keep the (possibly modified) record
//	    --   0  → keep the original record unchanged
//	    --  -1  → drop the record entirely
//	    return 1, record
//	end
package etl

import (
	"context"
	"fmt"
	"maps"
	"time"
	"xsiam/internal/model"

	lua "github.com/yuin/gopher-lua"
)

// LuaEngine executes Lua scripts against LogEntry records.
// It is safe for concurrent use — each Run call gets its own LuaState.
type LuaEngine struct{}

// NewLuaEngine constructs a LuaEngine.
func NewLuaEngine() *LuaEngine { return &LuaEngine{} }

// Run executes the Lua script against entry and tag.
// The script must define a function named "process" with the signature above.
//
// Returns:
//   - modified entry (may be the same pointer as input if code==0)
//   - drop  (true when the script returns -1)
//   - error (script compile/runtime errors — caller should log and skip)
func (le *LuaEngine) Run(script string, e *model.LogEntry, tag string) (*model.LogEntry, bool, error) {
	const maxScriptBytes = 64 * 1024
	if len(script) > maxScriptBytes {
		return e, false, fmt.Errorf("lua: script too large (%d bytes, max %d)", len(script), maxScriptBytes)
	}

	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer L.Close()

	// 只开放安全库（禁用 os/io/package/channel/coroutine）
	for _, pair := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(pair.fn))
		L.Push(lua.LString(pair.name))
		L.Call(1, 0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	L.SetContext(ctx)

	// Load the script
	if err := L.DoString(script); err != nil {
		return e, false, fmt.Errorf("lua compile: %w", err)
	}

	// Build the record table: merge struct fields + Fields map
	rec := L.NewTable()
	setStr := func(k, v string) {
		if v != "" {
			L.SetField(rec, k, lua.LString(v))
		}
	}
	setStr("hostname", e.Hostname)
	setStr("src_ip", e.SourceIP)
	setStr("agent_id", e.AgentID)
	setStr("session_id", e.SessionID)
	setStr("dataset", e.Dataset)
	setStr("tenant_id", e.TenantID)
	setStr("raw_log", e.RawLog)
	L.SetField(rec, "kind", lua.LNumber(e.Kind))
	for k, v := range e.Fields {
		switch val := v.(type) {
		case string:
			L.SetField(rec, k, lua.LString(val))
		case float64:
			L.SetField(rec, k, lua.LNumber(val))
		case int64:
			L.SetField(rec, k, lua.LNumber(val))
		case bool:
			L.SetField(rec, k, lua.LBool(val))
		default:
			L.SetField(rec, k, lua.LString(fmt.Sprintf("%v", val)))
		}
	}

	tsMs := lua.LNumber(e.EventTimestamp.UnixMilli())

	// Call process(tag, timestamp_ms, record)
	fn := L.GetGlobal("process")
	if fn == lua.LNil {
		return e, false, fmt.Errorf("lua: function 'process' not defined")
	}
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    2,
		Protect: true,
	}, lua.LString(tag), tsMs, rec); err != nil {
		return e, false, fmt.Errorf("lua runtime: %w", err)
	}

	// Read return values: (code, record_table)
	retRec := L.Get(-1)
	retCode := L.Get(-2)
	L.Pop(2)

	code, ok := retCode.(lua.LNumber)
	if !ok {
		return e, false, fmt.Errorf("lua: process() must return a number as first value, got %T", retCode)
	}

	switch int(code) {
	case -1:
		// Drop
		return nil, true, nil
	case 0:
		// Keep original unchanged
		return e, false, nil
	case 1:
		// Apply modifications from returned record table
		tbl, ok := retRec.(*lua.LTable)
		if !ok {
			return e, false, fmt.Errorf("lua: process() must return a table as second value, got %T", retRec)
		}
		return applyLuaTable(e, tbl), false, nil
	default:
		return e, false, fmt.Errorf("lua: unknown return code %d (expected -1, 0, or 1)", int(code))
	}
}

// applyLuaTable reads the Lua table back into a cloned LogEntry.
// Struct-level fields (hostname, src_ip, …) are applied directly;
// all other keys go into entry.Fields.
func applyLuaTable(orig *model.LogEntry, tbl *lua.LTable) *model.LogEntry {
	clone := *orig
	clone.Fields = make(map[string]any, len(orig.Fields))
	maps.Copy(clone.Fields, orig.Fields)

	tbl.ForEach(func(key, val lua.LValue) {
		k, ok := key.(lua.LString)
		if !ok {
			return
		}
		ks := string(k)
		switch ks {
		case "hostname":
			clone.Hostname = luaStr(val)
		case "src_ip":
			clone.SourceIP = luaStr(val)
		case "agent_id":
			clone.AgentID = luaStr(val)
		case "session_id":
			clone.SessionID = luaStr(val)
		case "dataset":
			clone.Dataset = luaStr(val)
		case "raw_log":
			clone.RawLog = luaStr(val)
		case "kind":
			if n, ok := val.(lua.LNumber); ok {
				clone.Kind = uint8(n)
			}
		case "event_timestamp_ms":
			if n, ok := val.(lua.LNumber); ok {
				clone.EventTimestamp = time.UnixMilli(int64(n)).UTC()
			}
		default:
			clone.Fields[ks] = luaToGo(val)
		}
	})
	return &clone
}

func luaStr(v lua.LValue) string {
	if s, ok := v.(lua.LString); ok {
		return string(s)
	}
	return v.String()
}

func luaToGo(v lua.LValue) any {
	switch val := v.(type) {
	case lua.LString:
		return string(val)
	case lua.LNumber:
		f := float64(val)
		if f == float64(int64(f)) {
			return int64(f)
		}
		return f
	case lua.LBool:
		return bool(val)
	case *lua.LTable:
		// Convert nested table to map[string]any
		m := map[string]any{}
		val.ForEach(func(k, v lua.LValue) {
			if ks, ok := k.(lua.LString); ok {
				m[string(ks)] = luaToGo(v)
			}
		})
		return m
	default:
		return v.String()
	}
}
