// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package jwtauth

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yeqown/go-qrcode/v2"
)

type qrWriter struct {
	writer io.Writer
}

// Close implements qrcode.Writer.
func (q qrWriter) Close() error {
	return nil
}

// Write implements qrcode.Writer.
func (q qrWriter) Write(mat qrcode.Matrix) error {
	b := mat.Bitmap()
	get := func(row int, col int) bool {
		if row < 0 || col < 0 {
			return false
		}
		if row >= len(b) || col >= len(b[row]) {
			return false
		}
		return b[row][col]
	}

	builder := strings.Builder{}

	var clearColors, setColors string
	colorterm := strings.TrimSpace(strings.ToLower(os.Getenv("COLORTERM")))
	if colorterm == "truecolor" || colorterm == "24bit" {
		setColors = "\033[38;2;255;255;255m" + // set forground color to white
			"\033[48;2;0;0;0m" // set background color to black
		clearColors = "\033[0m"
	}

	for row := -2; row < mat.Height()+2; row += 2 {
		builder.WriteString(setColors)

		for col := -2; col < mat.Width()+2; col += 1 {
			top := get(row, col)
			bottom := get(row+1, col)

			switch {
			case top && bottom:
				builder.WriteString(" ")
			case !top && bottom:
				builder.WriteString("▀")
			case top && !bottom:
				builder.WriteString("▄")
			case !top && !bottom:
				builder.WriteString("█")
			}
		}

		builder.WriteString(clearColors)
		builder.WriteString("\n")
	}

	_, err := fmt.Fprint(q.writer, builder.String())
	return err
}

func printQR(writer io.Writer, authURL string) {
	qr, err := qrcode.NewWith(authURL, qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionLow))
	if err != nil {
		fmt.Fprintln(writer, "could not generate QR code:", err.Error()) //nolint:errcheck
	}

	err = qr.Save(qrWriter{
		writer: writer,
	})
	if err != nil {
		fmt.Fprintln(writer, "could not display QR code:", err.Error()) //nolint:errcheck
	}
}
