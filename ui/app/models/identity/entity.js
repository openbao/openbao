/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { hasMany, attr } from '@ember-data/model';
import IdentityModel from './_base';
import apiPath from 'vault/utils/api-path';
import { capability } from 'vault/lib/capabilities';
import lazyCapabilities from 'vault/macros/lazy-capabilities';

export default class Model extends IdentityModel {
  get formFields() {
    return ['name', 'disabled', 'policies', 'metadata'];
  }

  @attr('string') name;

  @attr('boolean', {
    defaultValue: false,
    label: 'Disable entity',
    helpText: 'All associated tokens cannot be used, but are not revoked.',
  })
  disabled;

  @attr mergedEntityIds;

  @attr({
    editType: 'kv',
  })
  metadata;

  @attr({
    editType: 'yield',
    isSectionHeader: true,
  })
  policies;

  @attr('string', {
    readOnly: true,
  })
  creationTime;

  @attr('string', {
    readOnly: true,
  })
  lastUpdateTime;

  @hasMany('identity/entity-alias', { async: false, readOnly: true, inverse: 'entity' })
  aliases;

  @attr({
    readOnly: true,
  })
  groupIds;

  @attr({
    readOnly: true,
  })
  directGroupIds;

  @attr({
    readOnly: true,
  })
  inheritedGroupIds;

  // These currently use proxies, so we need to use .get instead
  // of direct property access, and the paths can sometimes
  // be null while loading.
  get canDelete() {
    return this.updatePath?.get('canDelete');
  }
  get canEdit() {
    return this.updatePath?.get('canUpdate');
  }
  get canRead() {
    return this.updatePath?.get('canRead');
  }
  get canAddAlias() {
    return this.aliasPath?.get('canCreate');
  }
  @lazyCapabilities(apiPath`sys/policies`) policyPath;
  get canCreatePolicies() {
    return this.policyPath?.get('canCreate');
  }

  @capability(apiPath`identity/entity/id/${'id'}`)
  updatePath;
  @capability(apiPath`identity/entity-alias`)
  aliasPath;
}
