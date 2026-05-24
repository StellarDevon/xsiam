// xlog_sender is a test tool that constructs a real XLOG binary frame and
// POSTs it to POST /internal/agent/log on :18090.
// It simulates a fluent-bit out_xsiam_log batch containing 3 process events
// and 2 auth events from a real agent.
//
// Usage:
//
//	go run ./cmd/xlog_sender
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	Magic        uint32 = 0x584C4F47 // "XLOG"
	Version      uint8  = 1
	TypeLogBatch uint8  = 0x01

	TagSchemaVersion uint8 = 0x01
	TagRowCount      uint8 = 0x02
	TagOrigSize      uint8 = 0x03
	TagColumns       uint8 = 0x04
	TagData          uint8 = 0x10
)

func main() {
	target := "http://localhost:18090/internal/agent/log"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	agentID := uint64(10001)
	now := time.Now().UTC()

	// ── Build TSV payload ──────────────────────────────────────────────────
	columns := "kind,hostname,src_ip,session_id,process_name,process_path,cmdline,pid,parent_pid,parent_name,user,file_hash,_time"

	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	rows := []string{
		// process events (kind=1)
		"process\tENDPOINT-REAL-01\t10.5.1.77\tsess-real-001\tpowershell.exe\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\t\"powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=\"\t9912\t4\tsvchost.exe\tuser1\t\t" + ts(-2*time.Minute),
		"process\tENDPOINT-REAL-01\t10.5.1.77\tsess-real-001\tcmd.exe\tC:\\Windows\\System32\\cmd.exe\tcmd.exe /c whoami\t9880\t9912\tpowershell.exe\tuser1\t\t" + ts(-90*time.Second),
		"process\tENDPOINT-REAL-01\t10.5.1.77\tsess-real-001\tnet.exe\tC:\\Windows\\System32\\net.exe\tnet user administrator /active:yes\t9920\t9880\tcmd.exe\tuser1\t\t" + ts(-60*time.Second),
		// auth events (kind=6)
		"auth\tENDPOINT-REAL-01\t10.5.1.77\tsess-real-002\t\t\t\t\t\t\tuser1\t\t" + ts(-45*time.Second),
		"auth\tENDPOINT-REAL-01\t192.168.100.5\tsess-real-003\t\t\t\t\t\t\tadministrator\t\t" + ts(-30*time.Second),
		// file event (kind=2)
		"file\tENDPOINT-REAL-01\t10.5.1.77\tsess-real-001\t\t\t\t\t\t\tuser1\tdeadbeef1234567890abcdef1234567890abcdef\t" + ts(-20*time.Second),
	}

	tsv := strings.Join(rows, "\n") + "\n"
	origSize := uint32(len(tsv))

	// Compress with zstd
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll([]byte(tsv), nil)

	// ── Build TLV body ─────────────────────────────────────────────────────
	var body bytes.Buffer
	writeTLV(&body, TagSchemaVersion, u16bytes(1))
	writeTLV(&body, TagRowCount, u32bytes(uint32(len(rows))))
	writeTLV(&body, TagOrigSize, u32bytes(origSize))
	writeTLV(&body, TagColumns, []byte(columns))
	writeTLV(&body, TagData, compressed)

	// ── Build XLOG frame header ────────────────────────────────────────────
	tag := []byte("winevent.wzcp")
	frame := make([]byte, 36+len(tag))
	binary.BigEndian.PutUint32(frame[0:4], Magic)
	frame[4] = Version
	frame[5] = TypeLogBatch
	frame[6] = 0 // flags
	frame[7] = uint8(len(tag))
	copy(frame[8:], tag)
	off := 8 + len(tag)
	binary.BigEndian.PutUint64(frame[off:], agentID)
	binary.BigEndian.PutUint64(frame[off+8:], 1) // seq
	binary.BigEndian.PutUint64(frame[off+16:], uint64(now.UnixMilli()))
	binary.BigEndian.PutUint32(frame[off+24:], uint32(body.Len()))

	var payload bytes.Buffer
	payload.Write(frame)
	payload.Write(body.Bytes())

	// ── POST to server ─────────────────────────────────────────────────────
	req, _ := http.NewRequest("POST", target, &payload)
	req.Header.Set("Content-Type", "application/x-xlog")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "POST failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		fmt.Printf("✓ batch accepted (%d rows, agent_id=%d)\n", len(rows), agentID)
	} else {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		fmt.Fprintf(os.Stderr, "✗ server returned %d: %s\n", resp.StatusCode, buf.String())
		os.Exit(1)
	}
}

func writeTLV(w *bytes.Buffer, tag uint8, value []byte) {
	w.WriteByte(tag)
	w.WriteByte(byte(len(value) >> 8))
	w.WriteByte(byte(len(value)))
	w.Write(value)
}

func u16bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u32bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
