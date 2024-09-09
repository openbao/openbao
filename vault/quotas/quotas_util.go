// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package quotas

func quotaTypes() []string {
	return []string{
		TypeRateLimit.String(),
	}
}
