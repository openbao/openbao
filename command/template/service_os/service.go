// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package service_os

var chanGraceExit = make(chan int)

// ShutdownChannel returns a channel that sends a message that a shutdown
// signal has been received for the service.
func Shutdown_Channel() <-chan int {
	return chanGraceExit
}
