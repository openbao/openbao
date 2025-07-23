// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrintQR(t *testing.T) {
	expectedQR := strings.Join([]string{
		"\033[38;2;255;255;255m\033[48;2;0;0;0m█████████████████████████\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ ▄▄▄▄▄ █▀ ▀███ ▄▄▄▄▄ ██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ █   █ █▄▀  ██ █   █ ██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ █▄▄▄█ █ ▄  ██ █▄▄▄█ ██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██▄▄▄▄▄▄▄█ ▀ █▄█▄▄▄▄▄▄▄██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██▄▄█▄▀█▄▄██ █ █   █▄▄▀██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m████ █▄ ▄▀ █▀▄ █▀█▀▀▄▀ ██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██▄▄▄█▄█▄▄▀▄█ ▀██ █▄██▀██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ ▄▄▄▄▄ █▄█▄ ▄▄█▀ ▄▄▄███\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ █   █ █▀▄▀█▀█▀█ ▄█▄ ██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██ █▄▄▄█ █▀█▄ ▄ ▄█▄█▄█▄██\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m██▄▄▄▄▄▄▄█▄▄▄█▄▄▄█▄██▄███\033[0m",
		"\033[38;2;255;255;255m\033[48;2;0;0;0m█████████████████████████\033[0m\n",
	}, "\n")

	t.Run("with 24-bit color support", func(t *testing.T) {
		t.Setenv("COLORTERM", "truecolor")
		b := bytes.Buffer{}
		printQR(&b, "https://auth.url/")
		assert.Equal(t, expectedQR, b.String())
	})

	t.Run("without 24-bit color support", func(t *testing.T) {
		t.Setenv("COLORTERM", "")
		b := bytes.Buffer{}
		printQR(&b, "https://auth.url/")
		assert.Equal(t, regexp.MustCompile("\033.*?m").ReplaceAllString(expectedQR, ""), b.String())
	})
}
