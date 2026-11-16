/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

// Unload a record from the store and catch any errors.
export default function removeRecord(store, record) {
  try {
    store.unloadRecord(record);
  } catch {
    // record may already be destroyed
  }
}
