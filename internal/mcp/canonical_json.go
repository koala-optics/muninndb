package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

func canonicalArgumentsSHA256(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return "", fmt.Errorf("arguments are not canonical JSON: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return "", fmt.Errorf("arguments contain trailing JSON")
	}
	if _, ok := value.(map[string]any); !ok {
		return "", fmt.Errorf("arguments must be a JSON object")
	}
	var canonical bytes.Buffer
	if err := writePythonCanonicalJSON(&canonical, value); err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(digest[:]), nil
}

func writePythonCanonicalJSON(dst *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		dst.WriteString("null")
	case bool:
		if v {
			dst.WriteString("true")
		} else {
			dst.WriteString("false")
		}
	case string:
		writePythonJSONString(dst, v)
	case json.Number:
		formatted, err := pythonJSONNumber(v.String())
		if err != nil {
			return err
		}
		dst.WriteString(formatted)
	case []any:
		dst.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				dst.WriteByte(',')
			}
			if err := writePythonCanonicalJSON(dst, item); err != nil {
				return err
			}
		}
		dst.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		dst.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				dst.WriteByte(',')
			}
			writePythonJSONString(dst, key)
			dst.WriteByte(':')
			if err := writePythonCanonicalJSON(dst, v[key]); err != nil {
				return err
			}
		}
		dst.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func pythonJSONNumber(raw string) (string, error) {
	if !strings.ContainsAny(raw, ".eE") {
		integer, ok := new(big.Int).SetString(raw, 10)
		if !ok {
			return "", fmt.Errorf("invalid JSON integer %q", raw)
		}
		return integer.String(), nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", fmt.Errorf("invalid JSON number %q", raw)
	}

	// Python's json encoder uses the shortest round-trippable digits, but keeps
	// finite floats in fixed notation when their normalized decimal exponent is
	// in [-4, 15]. Go's 'g' cutoff is [-4, 6), so choose the equivalent format
	// explicitly from the scientific exponent.
	scientific := strconv.FormatFloat(value, 'e', -1, 64)
	exponent, err := strconv.Atoi(scientific[strings.LastIndexByte(scientific, 'e')+1:])
	if err != nil {
		return "", fmt.Errorf("format JSON number %q: %w", raw, err)
	}
	if exponent >= -4 && exponent < 16 {
		formatted := strconv.FormatFloat(value, 'f', -1, 64)
		if !strings.Contains(formatted, ".") {
			formatted += ".0"
		}
		return formatted, nil
	}
	return normalizePythonExponent(scientific), nil
}

func normalizePythonExponent(value string) string {
	idx := strings.IndexByte(value, 'e')
	if idx < 0 {
		return value
	}
	mantissa, exponent := value[:idx], value[idx+1:]
	sign := "+"
	if strings.HasPrefix(exponent, "-") {
		sign = "-"
		exponent = exponent[1:]
	} else if strings.HasPrefix(exponent, "+") {
		exponent = exponent[1:]
	}
	for len(exponent) < 2 {
		exponent = "0" + exponent
	}
	return mantissa + "e" + sign + exponent
}

func writePythonJSONString(dst *bytes.Buffer, value string) {
	dst.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			dst.WriteString(`\\`)
		case '"':
			dst.WriteString(`\"`)
		case '\b':
			dst.WriteString(`\b`)
		case '\f':
			dst.WriteString(`\f`)
		case '\n':
			dst.WriteString(`\n`)
		case '\r':
			dst.WriteString(`\r`)
		case '\t':
			dst.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(dst, `\u%04x`, r)
			} else {
				dst.WriteRune(r)
			}
		}
	}
	dst.WriteByte('"')
}
