// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package schema validates tool arguments against the subset of JSON Schema
// that manifests use: object/array/string/number/integer/boolean, required,
// properties, additionalProperties, enum, min/max, minLength/maxLength,
// minItems/maxItems, pattern, exclusiveMinimum. It rejects, never coerces.
//
// A full draft-2020 validator would be a dependency; this subset is what a
// tool contract needs and is small enough to audit.
package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
)

type Schema struct {
	Type                 string             `json:"type"`
	Properties           map[string]*Schema `json:"properties"`
	Required             []string           `json:"required"`
	AdditionalProperties *bool              `json:"additionalProperties"`
	Items                *Schema            `json:"items"`
	Enum                 []json.RawMessage  `json:"enum"`
	Minimum              *float64           `json:"minimum"`
	Maximum              *float64           `json:"maximum"`
	ExclusiveMinimum     *float64           `json:"exclusiveMinimum"`
	MinLength            *int               `json:"minLength"`
	MaxLength            *int               `json:"maxLength"`
	MinItems             *int               `json:"minItems"`
	MaxItems             *int               `json:"maxItems"`
	Pattern              string             `json:"pattern"`
	Description          string             `json:"description"`
}

func Parse(raw json.RawMessage) (*Schema, error) {
	if len(raw) == 0 {
		return &Schema{Type: "object"}, nil
	}
	var s Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &s, nil
}

// Validate returns a list of human-readable violations (empty means valid).
func (s *Schema) Validate(v any) []string {
	var errs []string
	s.validate("$", v, &errs)
	return errs
}

func (s *Schema) validate(path string, v any, errs *[]string) {
	if s == nil {
		return
	}
	switch s.Type {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			*errs = append(*errs, path+": expected object")
			return
		}
		for _, req := range s.Required {
			if _, ok := m[req]; !ok {
				*errs = append(*errs, fmt.Sprintf("%s: missing required property %q", path, req))
			}
		}
		for k, val := range m {
			ps, known := s.Properties[k]
			if !known {
				if s.AdditionalProperties != nil && !*s.AdditionalProperties {
					*errs = append(*errs, fmt.Sprintf("%s: unexpected property %q", path, k))
				}
				continue
			}
			ps.validate(path+"."+k, val, errs)
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			*errs = append(*errs, path+": expected array")
			return
		}
		if s.MinItems != nil && len(a) < *s.MinItems {
			*errs = append(*errs, fmt.Sprintf("%s: fewer than %d items", path, *s.MinItems))
		}
		if s.MaxItems != nil && len(a) > *s.MaxItems {
			*errs = append(*errs, fmt.Sprintf("%s: more than %d items", path, *s.MaxItems))
		}
		for i, el := range a {
			s.Items.validate(fmt.Sprintf("%s[%d]", path, i), el, errs)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			*errs = append(*errs, path+": expected string")
			return
		}
		if s.MinLength != nil && len(str) < *s.MinLength {
			*errs = append(*errs, fmt.Sprintf("%s: shorter than %d", path, *s.MinLength))
		}
		if s.MaxLength != nil && len(str) > *s.MaxLength {
			*errs = append(*errs, fmt.Sprintf("%s: longer than %d", path, *s.MaxLength))
		}
		if s.Pattern != "" {
			if re, err := regexp.Compile(s.Pattern); err == nil && !re.MatchString(str) {
				*errs = append(*errs, fmt.Sprintf("%s: does not match %s", path, s.Pattern))
			}
		}
	case "number", "integer":
		f, ok := v.(float64)
		if !ok {
			*errs = append(*errs, path+": expected "+s.Type)
			return
		}
		if s.Type == "integer" && f != math.Trunc(f) {
			*errs = append(*errs, path+": expected integer")
		}
		if s.Minimum != nil && f < *s.Minimum {
			*errs = append(*errs, fmt.Sprintf("%s: below minimum %v", path, *s.Minimum))
		}
		if s.ExclusiveMinimum != nil && f <= *s.ExclusiveMinimum {
			*errs = append(*errs, fmt.Sprintf("%s: must be greater than %v", path, *s.ExclusiveMinimum))
		}
		if s.Maximum != nil && f > *s.Maximum {
			*errs = append(*errs, fmt.Sprintf("%s: above maximum %v", path, *s.Maximum))
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			*errs = append(*errs, path+": expected boolean")
		}
	case "":
		// untyped: accept
	default:
		*errs = append(*errs, fmt.Sprintf("%s: unsupported schema type %q", path, s.Type))
	}
	if len(s.Enum) > 0 {
		b, _ := json.Marshal(v)
		found := false
		for _, e := range s.Enum {
			if strings.TrimSpace(string(e)) == string(b) {
				found = true
				break
			}
		}
		if !found {
			*errs = append(*errs, path+": not in enum")
		}
	}
}
