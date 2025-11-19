// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
)

var (
	ErrJSONExceededMemory  = errors.New("input JSON exceeded maximum estimated memory limits")
	ErrJSONExceededStrings = errors.New("input JSON exceeded maximum number of strings")
)

type ctxKeyMaxRequestJsonMemory struct{}

func maximumJsonMemoryFromContext(ctx context.Context) int64 {
	maxJsonMemory := ctx.Value(ctxKeyMaxRequestJsonMemory{})
	if maxJsonMemory == nil {
		return -1
	}
	return maxJsonMemory.(int64)
}

func addMaximumJsonMemoryToContext(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, ctxKeyMaxRequestJsonMemory{}, limit)
}

type ctxKeyMaxRequestJsonStringCount struct{}

func maximumJsonStringsFromContext(ctx context.Context) int64 {
	maxJsonStrings := ctx.Value(ctxKeyMaxRequestJsonStringCount{})
	if maxJsonStrings == nil {
		return -1
	}
	return maxJsonStrings.(int64)
}

func addMaximumJsonStringsToContext(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, ctxKeyMaxRequestJsonStringCount{}, limit)
}

const (
	safeJSONCostBase   int64 = 8 + 8     // pointer to a value + type of pointer
	safeJSONCostNull   int64 = 1         // minimal overhead for null
	safeJSONCostBool   int64 = 1         // minimal overhead for booleans
	safeJSONCostNumber int64 = 8         // assume all numbers are 8-bytes
	safeJSONCostString int64 = 16        // assume 8 bytes for length + pointer to value
	safeJSONCostArray  int64 = 8 + 8 + 8 // assume 8 bytes each for length+cap of array and 8 more for a pointer to the start
	safeJSONCostObject int64 = 8 + 64    // 8 bytes for length of object + 64 bytes for bucket overhead
)

func memoryForToken(rawToken json.Token) int64 {
	switch token := rawToken.(type) {
	case json.Delim:
		switch token {
		case '[':
			return safeJSONCostBase + safeJSONCostArray
		case '{':
			return safeJSONCostBase + safeJSONCostObject
		default:
			// Closing braces shouldn't incur a cost.
			return 0
		}
	case bool:
		return safeJSONCostBase + safeJSONCostBool
	case float64, json.Number:
		return safeJSONCostBase + safeJSONCostNumber
	case string:
		return safeJSONCostBase + safeJSONCostString + int64(len(token))
	case nil:
		return safeJSONCostBase + safeJSONCostNull
	}

	return safeJSONCostBase
}

// EnforceJSONComplexityLimits is a shim to be placed between the raw underlying
// io.Reader and a JSON Unmarshaler to enforce limits on the number of
// memory (defined to be a new object, list, string, number, or constant),
// or number of distinct strings (currently defined to be all strings,
// including keys in a map, which aren't HMAC'd but will contribute to
// overhead).
func EnforceJSONComplexityLimits(ctx context.Context, reader io.Reader) (int64, int64, error) {
	maxMemory := maximumJsonMemoryFromContext(ctx)
	maxStrings := maximumJsonStringsFromContext(ctx)

	if maxMemory < 0 && maxStrings < 0 {
		// Nothing to do.
		return -1, -1, nil
	}

	var memory int64
	var strings int64

	dec := json.NewDecoder(reader)
	for {
		// Get the next token.
		token, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return memory, strings, err
		}

		// Limit our estimated cost to parse the input.
		tokenCost := memoryForToken(token)
		memory += tokenCost
		if maxMemory >= 0 && memory > maxMemory {
			return memory, strings, ErrJSONExceededMemory
		}

		// Separately limit the total number of strings to reduce cost
		// on the auditing subsystem.
		if _, ok := token.(string); ok {
			strings += 1
			if maxStrings >= 0 && strings > maxStrings {
				return memory, strings, ErrJSONExceededStrings
			}
		}
	}

	// Check for context cancellation.
	if err := ctx.Err(); err != nil {
		return memory, strings, err
	}

	return memory, strings, nil
}
