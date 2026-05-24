// Package ingest implements the XLOG binary framing protocol used to deliver
// compressed TSV log batches from endpoint agents to the XSIAM server.
//
// # Wire format
//
// Every XLOG TCP stream consists of back-to-back XLOG frames:
//
//	┌──────────────────────────────────────────────────────────────────┐
//	│  Fixed header  (32 bytes, big-endian)                            │
//	├────────┬───────┬───────┬───────┬──────────┬───────────────────  │
//	│ magic  │  ver  │ type  │ flags │ tag_len  │ tag (tag_len bytes)  │
//	│  4 B   │  1 B  │  1 B  │  1 B  │   1 B    │  0–255 bytes        │
//	├────────┴───────┴───────┴───────┴──────────┴─────────────────────┤
//	│ agent_id  8 B  │  seq  8 B  │  ts_ms  8 B  │  body_len  4 B     │
//	└──────────────────────────────────────────────────────────────────┘
//	followed by  body_len  bytes of TLV-encoded payload.
//
// # Magic bytes
//
//	0x58 0x4C 0x4F 0x47  →  ASCII "XLOG"
//
// First-byte disambiguation vs common protocols:
//
//	HTTP     0x47/0x50/0x48  (GET/POST/HTTP)
//	Syslog   0x3C            (<priority>)
//	TLS      0x16            (handshake)
//	WZCP     0x57            (W in WZCP)
//	SSH      0x53            (SSH-)
//	XLOG     0x58            ← unambiguous
//
// # TLV body tags
//
//	0x01  schema_version  u16      log schema version (currently 1)
//	0x02  row_count       u32      number of TSV rows in this batch
//	0x03  orig_size       u32      uncompressed TSV byte count
//	0x04  columns         []byte   comma-separated column names (UTF-8)
//	0x10  data            []byte   zstd-compressed TSV body
//
// # TSV body (after decompression)
//
// Plain UTF-8 tab-separated values, one row per line, no header row.
// Column order matches the "columns" TLV (tag 0x04).
// Timestamp column "_time" is RFC3339 when present.
package ingest

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Magic is the 4-byte frame identifier "XLOG" (0x584C4F47).
// Chosen so the first byte (0x58) does not collide with HTTP, syslog,
// TLS, WZCP, or SSH first bytes — enabling fast protocol multiplexing
// on a shared TCP listener.
const Magic uint32 = 0x584C4F47 // "XLOG"

// Protocol version this implementation targets.
const Version uint8 = 1

// Frame types.
const (
	TypeLogBatch  uint8 = 0x01 // compressed TSV log batch
	TypeAck       uint8 = 0x02 // server → agent acknowledgement
	TypeHeartbeat uint8 = 0x03 // keep-alive / channel probe
	TypeError     uint8 = 0x04 // server-side rejection with reason code
)

// TLV tags embedded in the frame body.
const (
	TagSchemaVersion uint8 = 0x01 // u16 log schema version
	TagRowCount      uint8 = 0x02 // u32 number of TSV rows
	TagOrigSize      uint8 = 0x03 // u32 pre-compression byte count
	TagColumns       uint8 = 0x04 // comma-separated column name list
	TagData          uint8 = 0x10 // zstd-compressed TSV payload
)

// fixedHeaderSize is the on-wire size of the invariant part of the header
// (magic + ver + type + flags + tag_len = 8 bytes, then agent_id + seq +
// ts_ms + body_len = 28 bytes → total 36 bytes before the variable tag).
const fixedHeaderSize = 36

// FrameHeader is the decoded fixed portion of an XLOG frame.
type FrameHeader struct {
	Magic    uint32
	Version  uint8
	Type     uint8
	Flags    uint8
	Tag      string // 0–255 bytes; log source tag e.g. "winevent", "sysmon"
	AgentID  uint64
	Seq      uint64
	TsMs     uint64 // milliseconds since Unix epoch
	BodyLen  uint32
}

// ReadHeader reads and validates a single XLOG frame header from r.
// Returns ErrBadMagic if the magic bytes do not match.
func ReadHeader(r io.Reader) (FrameHeader, error) {
	// Read fixed portion: magic(4) + ver(1) + type(1) + flags(1) + tag_len(1) = 8
	var fixed [8]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return FrameHeader{}, fmt.Errorf("xlog: read fixed header: %w", err)
	}
	magic := binary.BigEndian.Uint32(fixed[0:4])
	if magic != Magic {
		return FrameHeader{}, &ErrBadMagic{Got: magic}
	}
	ver := fixed[4]
	typ := fixed[5]
	flags := fixed[6]
	tagLen := fixed[7]

	// Read variable-length tag.
	tag := make([]byte, tagLen)
	if tagLen > 0 {
		if _, err := io.ReadFull(r, tag); err != nil {
			return FrameHeader{}, fmt.Errorf("xlog: read tag: %w", err)
		}
	}

	// Read remaining scalar fields: agent_id(8) + seq(8) + ts_ms(8) + body_len(4) = 28
	var tail [28]byte
	if _, err := io.ReadFull(r, tail[:]); err != nil {
		return FrameHeader{}, fmt.Errorf("xlog: read header tail: %w", err)
	}
	return FrameHeader{
		Magic:   magic,
		Version: ver,
		Type:    typ,
		Flags:   flags,
		Tag:     string(tag),
		AgentID: binary.BigEndian.Uint64(tail[0:8]),
		Seq:     binary.BigEndian.Uint64(tail[8:16]),
		TsMs:    binary.BigEndian.Uint64(tail[16:24]),
		BodyLen: binary.BigEndian.Uint32(tail[24:28]),
	}, nil
}

// WriteHeader serialises hdr into buf (which must be pre-allocated to the
// correct size: fixedHeaderSize + len(hdr.Tag)).
func WriteHeader(hdr FrameHeader) []byte {
	tag := []byte(hdr.Tag)
	if len(tag) > 255 {
		tag = tag[:255]
	}
	buf := make([]byte, fixedHeaderSize+len(tag))
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = hdr.Version
	buf[5] = hdr.Type
	buf[6] = hdr.Flags
	buf[7] = uint8(len(tag))
	copy(buf[8:], tag)
	off := 8 + len(tag)
	binary.BigEndian.PutUint64(buf[off:], hdr.AgentID)
	binary.BigEndian.PutUint64(buf[off+8:], hdr.Seq)
	binary.BigEndian.PutUint64(buf[off+16:], hdr.TsMs)
	binary.BigEndian.PutUint32(buf[off+24:], hdr.BodyLen)
	return buf
}

// ErrBadMagic is returned when the first 4 bytes are not "XLOG".
type ErrBadMagic struct{ Got uint32 }

func (e *ErrBadMagic) Error() string {
	return fmt.Sprintf("xlog: bad magic 0x%08X (expected 0x%08X)", e.Got, Magic)
}

// IsMagicError reports whether err is an ErrBadMagic — useful for
// multiplexing: if the first 4 bytes don't match, hand the connection
// to the next protocol handler.
func IsMagicError(err error) bool {
	_, ok := err.(*ErrBadMagic)
	return ok
}
