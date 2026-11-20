/**
 * SPDX-License-Identifier: MPL-2.0
 */

export default function subkeyPaths(source, parent = []) {
  return Object.entries(source || {}).flatMap(([key, value]) => {
    const path = [...parent, key];
    if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length) {
      return subkeyPaths(value, path);
    }
    return [path];
  });
}
