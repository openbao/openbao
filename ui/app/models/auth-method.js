/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { belongsTo, attr } from '@ember-data/model';
import { computed } from '@ember/object'; // eslint-disable-line
import { inject as service } from '@ember/service';
import fieldToAttrs, { expandAttributeMeta } from 'vault/utils/field-to-attrs';
import apiPath from 'vault/utils/api-path';
import { capability } from 'vault/lib/capabilities';
import { withModelValidations } from 'vault/decorators/model-validations';

const validations = {
  path: [
    { type: 'presence', message: "Path can't be blank." },
    {
      type: 'containsWhiteSpace',
      message:
        "Path contains whitespace. If this is desired, you'll need to encode it with %20 in API requests.",
      level: 'warn',
    },
  ],
};

// unsure if ember-api-actions will work on native JS class model
// for now create class to use validations and then use classic extend pattern
@withModelValidations(validations)
class AuthMethodModel extends Model {}
export default class ModelExport extends AuthMethodModel {
  @service store;

  @belongsTo('mount-config', { async: false, inverse: null }) config; // one-to-none that replaces former fragment
  @attr('string') path;
  @attr('string') accessor;
  @attr('string') name;
  @attr('string') type;
  // namespaces introduced types with a `ns_` prefix for built-in engines
  // so we need to strip that to normalize the type
  get methodType() {
    const type = this.type;
    if (!type) {
      return '';
    }
    return type.replace(/^ns_/, '');
  }
  @attr('string', {
    editType: 'textarea',
  })
  description;
  @attr('boolean', {
    helpText:
      'When Replication is enabled, a local mount will not be replicated across clusters. This can only be specified at mount time.',
  })
  local;
  @attr('boolean', {
    helpText:
      'When enabled - if a seal supporting seal wrapping is specified in the configuration, all critical security parameters (CSPs) in this backend will be seal wrapped. (For K/V mounts, all values will be seal wrapped.) This can only be specified at mount time.',
  })
  sealWrap;

  // used when the `auth` prefix is important,
  // currently only when setting perf mount filtering
  get apiPath() {
    return `auth/${this.path}`;
  }
  get localDisplay() {
    return this.local ? 'local' : 'replicated';
  }

  get tuneAttrs() {
    const { methodType } = this;
    let tuneAttrs;
    // token_type should not be tuneable for the token auth method
    if (methodType === 'token') {
      tuneAttrs = [
        'description',
        'config.{listingVisibility,defaultLeaseTtl,maxLeaseTtl,auditNonHmacRequestKeys,auditNonHmacResponseKeys,passthroughRequestHeaders}',
      ];
    } else {
      tuneAttrs = [
        'description',
        'config.{listingVisibility,defaultLeaseTtl,maxLeaseTtl,tokenType,auditNonHmacRequestKeys,auditNonHmacResponseKeys,passthroughRequestHeaders}',
      ];
    }
    return expandAttributeMeta(this, tuneAttrs);
  }

  get formFields() {
    return [
      'type',
      'path',
      'description',
      'accessor',
      'local',
      'sealWrap',
      'config.{listingVisibility,defaultLeaseTtl,maxLeaseTtl,tokenType,auditNonHmacRequestKeys,auditNonHmacResponseKeys,passthroughRequestHeaders}',
    ];
  }

  get formFieldGroups() {
    return [
      { default: ['path'] },
      {
        'Method Options': [
          'description',
          'config.listingVisibility',
          'local',
          'sealWrap',
          'config.{defaultLeaseTtl,maxLeaseTtl,tokenType,auditNonHmacRequestKeys,auditNonHmacResponseKeys,passthroughRequestHeaders}',
        ],
      },
    ];
  }

  get attrs() {
    return expandAttributeMeta(this, this.formFields);
  }

  get fieldGroups() {
    return fieldToAttrs(this, this.formFieldGroups);
  }
  // These currently use proxies, so we need to use .get instead
  // of direct property access, and the paths can sometimes
  // be null while loading.
  get canDisable() {
    return this.deletePath?.get('canDelete');
  }
  get canEdit() {
    return this.configPath?.get('canUpdate');
  }

  tune(data) {
    return this.store.adapterFor('auth-method').tune(this.path, data);
  }

  @capability(apiPath`sys/auth/${'id'}`)
  deletePath;

  @capability(function (context) {
    if (context.type === 'aws') {
      return apiPath`auth/${'id'}/config/client`.call(this, context);
    } else {
      return apiPath`auth/${'id'}/config`.call(this, context);
    }
  })
  configPath;
}
