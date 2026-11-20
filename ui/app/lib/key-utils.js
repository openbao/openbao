/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

function keyIsFolder(key) {
  return key ? !!key.match(/\/$/) : false;
}

function keyPartsForKey(key) {
  if (!key) {
    return null;
  }
  var isFolder = keyIsFolder(key);
  var parts = key.split('/');
  if (isFolder) {
    parts.pop();
  }
  return parts.length > 1 ? parts : null;
}

function parentKeyForKey(key) {
  var parts = keyPartsForKey(key);
  if (!parts) {
    return null;
  }
  return parts.slice(0, -1).join('/') + '/';
}

function keyWithoutParentKey(key) {
  return key ? key.replace(parentKeyForKey(key), '') : null;
}

function ancestorKeysForKey(key) {
  var ancestors = [],
    parentKey = parentKeyForKey(key);

  while (parentKey) {
    ancestors.unshift(parentKey);
    parentKey = parentKeyForKey(parentKey);
  }

  return ancestors;
}

function keyWhitespaceWarning(key) {
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

function subkeyPaths(source, parent = []) {
  return Object.entries(source || {}).flatMap(([key, value]) => {
    const path = [...parent, key];
    if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length) {
      return subkeyPaths(value, path);
    }
    return [path];
  });
}

export default {
  keyIsFolder,
  keyPartsForKey,
  parentKeyForKey,
  keyWithoutParentKey,
  ancestorKeysForKey,
  keyWhitespaceWarning,
  subkeyPaths,
};
