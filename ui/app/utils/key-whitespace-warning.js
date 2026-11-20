/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

export default function keyWhitespaceWarning(key) {
  const leading = key !== key.trimStart();
  const trailing = key !== key.trimEnd();
  if (leading && trailing) {
    return 'key starts and ends with a whitespace';
  }
  if (leading) {
    return 'key starts with a whitespace';
  }
  if (trailing) {
    return 'key ends with a whitespace';
  }
  return null;
}
