package ingest

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TLV represents a single Type-Length-Value field decoded from an XLOG body.
type TLV struct {
	Tag   uint8
	Value []byte
}

// DecodeTLVs reads all TLV fields from body until exhausted.
// Format per field:  T(1B) + L(2B big-endian) + V(L bytes)
func DecodeTLVs(body []byte) ([]TLV, error) {
	var out []TLV
	for len(body) > 0 {
		if len(body) < 3 {
			return nil, fmt.Errorf("xlog tlv: truncated header (need 3, have %d)", len(body))
		}
		tag := body[0]
		length := binary.BigEndian.Uint16(body[1:3])
		body = body[3:]
		if int(length) > len(body) {
			return nil, fmt.Errorf("xlog tlv: tag 0x%02X length %d exceeds body remainder %d", tag, length, len(body))
		}
		val := make([]byte, length)
		copy(val, body[:length])
		out = append(out, TLV{Tag: tag, Value: val})
		body = body[length:]
	}
	return out, nil
}

// EncodeTLV serialises a single T+L+V field into w.
func EncodeTLV(w io.Writer, tag uint8, value []byte) error {
	if len(value) > 0xFFFF {
		return fmt.Errorf("xlog tlv: value length %d exceeds u16 max", len(value))
	}
	hdr := [3]byte{tag, byte(len(value) >> 8), byte(len(value))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(value) > 0 {
		_, err := w.Write(value)
		return err
	}
	return nil
}

// LogBatch holds the decoded contents of a TypeLogBatch frame body.
type LogBatch struct {
	SchemaVersion uint16
	RowCount      uint32
	OrigSize      uint32
	Columns       []string // parsed from comma-separated TagColumns value
	CompressedTSV []byte   // raw zstd bytes from TagData
}

// DecodeBatch parses the TLV fields of a TypeLogBatch frame body into a
// LogBatch.  The caller is responsible for decompressing CompressedTSV.
func DecodeBatch(body []byte) (LogBatch, error) {
	tlvs, err := DecodeTLVs(body)
	if err != nil {
		return LogBatch{}, err
	}
	var b LogBatch
	for _, t := range tlvs {
		switch t.Tag {
		case TagSchemaVersion:
			if len(t.Value) < 2 {
				return LogBatch{}, fmt.Errorf("xlog: tag 0x01 too short")
			}
			b.SchemaVersion = binary.BigEndian.Uint16(t.Value)
		case TagRowCount:
			if len(t.Value) < 4 {
				return LogBatch{}, fmt.Errorf("xlog: tag 0x02 too short")
			}
			b.RowCount = binary.BigEndian.Uint32(t.Value)
		case TagOrigSize:
			if len(t.Value) < 4 {
				return LogBatch{}, fmt.Errorf("xlog: tag 0x03 too short")
			}
			b.OrigSize = binary.BigEndian.Uint32(t.Value)
		case TagColumns:
			b.Columns = splitColumns(t.Value)
		case TagData:
			b.CompressedTSV = t.Value
		}
	}
	if len(b.CompressedTSV) == 0 {
		return LogBatch{}, fmt.Errorf("xlog: missing TagData (0x10) in batch body")
	}
	return b, nil
}

// splitColumns splits a comma-separated column list byte slice into strings.
func splitColumns(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var cols []string
	start := 0
	for i, c := range b {
		if c == ',' {
			cols = append(cols, string(b[start:i]))
			start = i + 1
		}
	}
	cols = append(cols, string(b[start:]))
	return cols
}
