// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package schema

import (
	"encoding/json"
	"testing"
)

const cart = `{"type":"object","properties":{"customer_id":{"type":"string","minLength":1},
"items":{"type":"array","minItems":1,"maxItems":3,"items":{"type":"string"}},
"tip":{"type":"number","minimum":0,"maximum":1},"mode":{"type":"string","enum":["pickup","delivery"]}},
"required":["customer_id","items"],"additionalProperties":false}`

func TestValidate(t *testing.T) {
	s, err := Parse(json.RawMessage(cart))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"ok", `{"customer_id":"c1","items":["a"],"tip":0.2,"mode":"pickup"}`, 0},
		{"missing required", `{"items":["a"]}`, 1},
		{"extra property", `{"customer_id":"c1","items":["a"],"sql":"drop"}`, 1},
		{"wrong type", `{"customer_id":1,"items":"a"}`, 2},
		{"too many items", `{"customer_id":"c1","items":["a","b","c","d"]}`, 1},
		{"enum", `{"customer_id":"c1","items":["a"],"mode":"teleport"}`, 1},
		{"range", `{"customer_id":"c1","items":["a"],"tip":1.5}`, 1},
	}
	for _, c := range cases {
		var v any
		json.Unmarshal([]byte(c.in), &v)
		if got := s.Validate(v); len(got) != c.want {
			t.Errorf("%s: want %d violations, got %v", c.name, c.want, got)
		}
	}
}
