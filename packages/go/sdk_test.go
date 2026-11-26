package http6

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTrustPinsAndComparisons(t *testing.T) {
	if pins("bad") == nil {
		t.Fatal("accepted invalid pin")
	}
	if e := compare(map[string]any{"x": json.Number("1")}, map[string]any{"x": json.Number("2")}, "x"); e == nil {
		t.Fatal("accepted modified evidence")
	}
	if e := compare(map[string]any{}, map[string]any{}, "x"); e == nil {
		t.Fatal("accepted missing evidence")
	}
}
func TestRequestLimit(t *testing.T) {
	c := Client{}
	if _, e := c.InvokeRaw(bytes.Repeat([]byte{'x'}, 65537)); e == nil {
		t.Fatal("accepted oversized request")
	}
}
