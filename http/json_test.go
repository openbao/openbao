// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/openbao/openbao/helper/buffer"
	"github.com/stretchr/testify/require"
)

func TestSafeJSONReader(t *testing.T) {
	t.Parallel()

	tests := []string{
		`null`,
		`false`,
		`true`,
		`1.0`,
		`-10`,
		`52`,
		`"hello"`,
		`["hello"]`,
		`{"hello":"world"}`,
		`{"hello":null}`,
		`{"hello":true}`,
		`{"hello":false}`,
		`{"hello":1.0}`,
		`{"hello":-1.0}`,
		`{"hello":10}`,
		`{"hello":-10}`,
		`{"hello":1e2}`,
		`{"hello":{"there":"home"}}`,
		`{"hello":{"home": null}}`,
		`"he\tllo"`,
		`"he{}llo"`,
		`{ "hello" : [ "world", "earth" ] }`,
		`{ "hello"    : [ "world", "earth" ] }`,
	}

	for index, test := range tests {
		// First compute actual values.
		ctx := addMaximumJsonMemoryToContext(context.Background(), math.MaxInt64)
		ctx = addMaximumJsonStringsToContext(ctx, math.MaxInt64)
		actualMemory, actualStrings, err := EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
		require.NoError(t, err)

		// Setting these actual values should allow parsing to succeed and
		// be consistent.
		ctx = addMaximumJsonMemoryToContext(context.Background(), actualMemory)
		newMemory, newStrings, err := EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
		require.NoError(t, err)
		require.Equal(t, actualMemory, newMemory)
		require.Equal(t, actualStrings, newStrings)

		ctx = addMaximumJsonStringsToContext(context.Background(), actualStrings)
		newMemory, newStrings, err = EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
		require.NoError(t, err)
		require.Equal(t, actualMemory, newMemory)
		require.Equal(t, actualStrings, newStrings)

		ctx = addMaximumJsonMemoryToContext(context.Background(), actualMemory)
		ctx = addMaximumJsonStringsToContext(ctx, actualStrings)
		newMemory, newStrings, err = EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
		require.NoError(t, err)
		require.Equal(t, actualMemory, newMemory)
		require.Equal(t, actualStrings, newStrings)

		// Parsing it to JSON should also work.
		var out interface{}
		body, err := buffer.NewSeekableReader(bytes.NewReader([]byte(test)))
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, "POST", "/v1/sys/testing", body)
		require.NoError(t, err)

		err = parseJSONRequest(req, nil, &out)
		require.NoError(t, err)

		// Decreasing memory by one, if allowed, should cause a failure. This
		// shows the bound is tight.
		if actualMemory > 0 {
			ctx = addMaximumJsonMemoryToContext(context.Background(), actualMemory-1)
			_, _, err := EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
			require.Error(t, err, "test case %d: %q", index, test)
			require.ErrorContains(t, err, ErrJSONExceededMemory.Error())

			req, err := http.NewRequestWithContext(ctx, "POST", "/v1/sys/testing", bytes.NewBufferString(test))
			require.NoError(t, err)

			err = parseJSONRequest(req, nil, &out)
			require.Error(t, err)
			require.ErrorContains(t, err, ErrJSONExceededMemory.Error())
		}

		// Decreasing strings by one, if allowed, should cause a failure. This
		// shows the bound is tight.
		if actualStrings > 0 {
			ctx = addMaximumJsonStringsToContext(context.Background(), actualStrings-1)
			_, _, err := EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
			require.Error(t, err, "test case %d: %q", index, test)
			require.ErrorContains(t, err, ErrJSONExceededStrings.Error())

			req, err := http.NewRequestWithContext(ctx, "POST", "/v1/sys/testing", bytes.NewBufferString(test))
			require.NoError(t, err)

			err = parseJSONRequest(req, nil, &out)
			require.Error(t, err)
			require.ErrorContains(t, err, ErrJSONExceededStrings.Error())
		}

		// Decreasing both bounds should fail.
		if actualStrings > 0 && actualMemory > 0 {
			ctx = addMaximumJsonMemoryToContext(context.Background(), actualMemory-1)
			ctx = addMaximumJsonStringsToContext(ctx, actualStrings-1)
			_, _, err := EnforceJSONComplexityLimits(ctx, bytes.NewBufferString(test))
			require.Error(t, err, "test case %d: %q", index, test)
		}
	}
}

func makeLongEmptyList(size int) interface{} {
	var list []interface{}
	for range size {
		list = append(list, map[string]interface{}{})
	}
	return list
}

func makeLongString(size int) interface{} {
	var x string
	for i := range size {
		x += fmt.Sprintf("%d", i%10)
	}
	return x
}

func makeLargeMap(size int) interface{} {
	data := map[string]interface{}{}
	for i := range size {
		data[fmt.Sprintf("%d", i)] = i
	}
	return data
}

func makeRandomMap(size int) interface{} {
	data := map[string]interface{}{}
	for i := range size / 10 {
		switch i % 3 {
		case 0:
			data[fmt.Sprintf("%d", i)] = makeLongString(size)
		case 1:
			data[fmt.Sprintf("%d", i)] = makeLargeMap(size / 10)
		case 2:
			data[fmt.Sprintf("%d", i)] = makeLongEmptyList(size / 10)
		}
	}
	return data
}

func fakeSizeOf(t *testing.T, input []byte) int64 {
	min := fakeSizeOfInternal(t, input)
	for i := 0; i < 15; i++ {
		time.Sleep(5 * time.Millisecond)

		v := fakeSizeOfInternal(t, input)
		if v < min {
			min = v
		}
	}

	return min
}

func fakeSizeOfInternal(t *testing.T, input []byte) int64 {
	// See https://github.com/go-json-experiment/jsonbench/blob/a05b1d16f57185a257748aed79c08336adc2caa5/bench_test.go.
	var obj interface{}

	// Run GC multiple times to fully clear any sync.Pools.
	for i := 0; i < 10; i++ {
		runtime.GC()
	}

	// Measure allocations beforehand.
	var statsBefore runtime.MemStats
	var statsAfter runtime.MemStats
	runtime.ReadMemStats(&statsBefore)

	err := json.Unmarshal(input, &obj)
	require.NoError(t, err)

	// Run GC multiple times to fully clear any sync.Pools.
	for i := 0; i < 10; i++ {
		runtime.GC()
	}

	// Measure allocations afterwards.
	runtime.ReadMemStats(&statsAfter)

	allocBytes := statsAfter.TotalAlloc - statsBefore.TotalAlloc
	return int64(allocBytes)
}

func TestSafeJSONReaderValidateSizes(t *testing.T) {
	t.Skip("Skipping expensive test by default; use for debugging cost estimates")

	// We build various objects, marshal them to JSON and try to measure
	// expected versus actual final allocation size.
	tests := []*struct {
		name  string
		input interface{}
	}{
		{"string", "string"},
		{"int", 42},
		{"simple map", map[string]interface{}{"a": "b"}},
		{"simple string list", []string{"a", "b"}},
		{"simple int list", []int{1, 2, 3, 4}},
		{"long empty list", makeLongEmptyList(10000)},
		{"long string", makeLongString(100000)},
		{"large map", makeLargeMap(10000)},
		{"large random map", makeRandomMap(10000)},
	}

	for _, test := range tests {
		// Not a Seekable reader.
		output, err := json.Marshal(test.input)
		require.NoError(t, err)

		buf := bytes.NewBuffer(output)

		ctx := context.Background()
		ctx = addMaximumJsonMemoryToContext(ctx, math.MaxInt64)
		ctx = addMaximumJsonStringsToContext(ctx, math.MaxInt64)

		memoryEstimate, _, err := EnforceJSONComplexityLimits(ctx, buf)
		require.NoError(t, err)

		memoryActual := fakeSizeOf(t, output)

		preview := string(output)
		if len(preview) > 75 {
			preview = preview[0:75]
		}

		t.Logf("name: %v\n\testimated: %v\n\tactual: %v\n\tjson: %q (%v bytes)", test.name, memoryEstimate, memoryActual, preview, len(output))

		// Allow within an order of magnitude, with a bit extra to
		// handle hiccups during CI.
		require.LessOrEqual(t, memoryEstimate, 20*memoryActual)
		require.LessOrEqual(t, memoryActual, 20*memoryEstimate)
	}
}
