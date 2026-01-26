// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build tools

// This file ensures tool dependencies are kept in sync.  This is the
// recommended way of doing this according to
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// To install the following tools at the version used by this repo run:
// $ make bootstrap
// or
// $ go generate -tags tools tools/tools.go

package tools

//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go
//go:generate go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
//go:generate go install github.com/favadi/protoc-go-inject-tag
//go:generate go install gotest.tools/gotestsum
//go:generate go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint
import (
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"

	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"

	_ "github.com/favadi/protoc-go-inject-tag"

	_ "gotest.tools/gotestsum"

	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
)
