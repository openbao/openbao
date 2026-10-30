/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model, { attr } from '@ember-data/model';
import { computed } from '@ember/object';
import { alias, or } from '@ember/object/computed';
import lazyCapabilities, { apiPath } from 'vault/macros/lazy-capabilities';
import fieldToAttrs, { expandAttributeMeta } from 'vault/utils/field-to-attrs';
import { AVAILABLE_PLUGIN_TYPES } from '../../utils/database-helpers';

/**
 * fieldsToGroups helper fn
 * @param {array} arr any subset of "fields" from AVAILABLE_PLUGIN_TYPES
 * @param {*} key item by which to group the fields. If item has no group it will be under "default"
 * @returns array of objects where the key is default or the name of the option group, and the value is an array of attr names
 */
const fieldsToGroups = function (arr, key = 'subgroup') {
  const fieldGroups = [];
  const byGroup = arr.reduce(function (rv, x) {
    (rv[x[key]] = rv[x[key]] || []).push(x);
    return rv;
  }, {});
  Object.keys(byGroup).forEach((key) => {
    const attrsArray = byGroup[key].map((obj) => obj.attr);
    const group = key === 'undefined' ? 'default' : key;
    fieldGroups.push({ [group]: attrsArray });
  });
  return fieldGroups;
};

export default Model.extend({
  backend: attr('string', {
    readOnly: true,
  }),
  // required
  name: attr('string', {
    label: 'Connection name',
  }),
  plugin_name: attr('string', {
    label: 'Database plugin',
    possibleValues: AVAILABLE_PLUGIN_TYPES,
    noDefault: true,
  }),

  // standard
  verify_connection: attr('boolean', {
    label: 'Connection will be verified',
    defaultValue: true,
  }),
  allowed_roles: attr('array', {
    readOnly: true,
  }),
  password_policy: attr('string', {
    label: 'Use custom password policy',
    editType: 'optionalText',
    subText: 'Specify the name of an existing password policy.',
    defaultSubText:
      'Unless a custom policy is specified, OpenBao will use a default: 20 characters with at least 1 uppercase, 1 lowercase, 1 number, and 1 dash character.',
    defaultShown: 'Default',
    docLink: '/docs/concepts/password-policies',
  }),

  // common fields
  connection_url: attr('string', {
    label: 'Connection URL',
    subText:
      'The connection string used to connect to the database. This allows for simple templating of username and password of the root user in the {{field_name}} format.',
  }),
  url: attr('string', {
    label: 'URL',
    subText: `The URL for Elasticsearch's API ("https://localhost:9200").`,
  }),
  username: attr('string', {
    subText: `The name of the user to use as the "root" user when connecting to the database.`,
  }),
  password: attr('string', {
    subText: 'The password to use when connecting with the above username.',
    editType: 'password',
  }),

  // optional
  hosts: attr('string', {}),
  host: attr('string', {}),
  port: attr('string', {}),
  write_concern: attr('string', {
    subText: 'Optional. Must be in JSON. See our documentation for help.',
    allowReset: true,
    editType: 'json',
    theme: 'hashi short',
    defaultShown: 'Default',
  }),
  username_template: attr('string', {
    editType: 'optionalText',
    subText: 'Enter the custom username template to use.',
    defaultSubText:
      'Template describing how dynamic usernames are generated. OpenBao will use the default for this plugin.',
    docLink: '/docs/concepts/username-templating',
    defaultShown: 'Default',
  }),
  max_open_connections: attr('number', {
    defaultValue: 4,
  }),
  max_idle_connections: attr('number', {
    defaultValue: 0,
  }),
  max_connection_lifetime: attr('string', {
    defaultValue: '0s',
  }),
  tls: attr('string', {
    label: 'TLS Certificate Key',
    helpText:
      'x509 certificate for connecting to the database. This must be a PEM encoded version of the private key and the certificate combined.',
    editType: 'file',
  }),
  tls_ca: attr('string', {
    label: 'TLS CA',
    helpText: 'PEM-encoded CA certificate bundle used to verify the server certificate.',
    editType: 'file',
  }),
  tls_certificate: attr('string', {
    label: 'TLS certificate',
    helpText: 'PEM-encoded client certificate for mutual TLS. Must be set together with the TLS key.',
    editType: 'file',
  }),
  tls_key: attr('string', {
    label: 'TLS key',
    helpText: 'PEM-encoded private key for the TLS certificate.',
    editType: 'file',
  }),
  tls_skip_verify: attr('boolean', {
    label: 'Skip TLS verification',
    subText: 'Skips verification of the server certificate. Intended for development only.',
    defaultValue: false,
  }),
  use_tls: attr('boolean', {
    label: 'Use TLS',
    subText: 'Connect with TLS even when no other TLS option is set.',
    defaultValue: false,
  }),
  tls_server_name: attr('string', {
    label: 'TLS server name',
    subText: 'If set, this name is used to set the SNI host when connecting via 1TLS.',
  }),
  root_rotation_statements: attr({
    subText: `The database statements to be executed to rotate the root user's credentials. If nothing is entered, OpenBao will use a reasonable default.`,
    editType: 'stringArray',
    defaultShown: 'Default',
  }),

  isAvailablePlugin: computed('plugin_name', function () {
    return !!AVAILABLE_PLUGIN_TYPES.find((a) => a.value === this.plugin_name);
  }),

  showAttrs: computed('plugin_name', function () {
    const fields = AVAILABLE_PLUGIN_TYPES.find((a) => a.value === this.plugin_name)
      .fields.filter((f) => f.show !== false)
      .map((f) => f.attr);
    fields.push('allowed_roles');
    return expandAttributeMeta(this, fields);
  }),

  fieldAttrs: computed('plugin_name', function () {
    // for both create and edit fields
    let fields = ['plugin_name', 'name', 'connection_url', 'verify_connection', 'password_policy'];
    if (this.plugin_name) {
      fields = AVAILABLE_PLUGIN_TYPES.find((a) => a.value === this.plugin_name)
        .fields.filter((f) => !f.group)
        .map((field) => field.attr);
    }
    return expandAttributeMeta(this, fields);
  }),

  pluginFieldGroups: computed('plugin_name', function () {
    if (!this.plugin_name) {
      return null;
    }
    const pluginFields = AVAILABLE_PLUGIN_TYPES.find((a) => a.value === this.plugin_name).fields.filter(
      (f) => f.group === 'pluginConfig'
    );
    const groups = fieldsToGroups(pluginFields, 'subgroup');
    return fieldToAttrs(this, groups);
  }),

  statementFields: computed('plugin_name', function () {
    if (!this.plugin_name) {
      return expandAttributeMeta(this, ['root_rotation_statements']);
    }
    const fields = AVAILABLE_PLUGIN_TYPES.find((a) => a.value === this.plugin_name)
      .fields.filter((f) => f.group === 'statements')
      .map((field) => field.attr);
    return expandAttributeMeta(this, fields);
  }),

  /* CAPABILITIES */
  editConnectionPath: lazyCapabilities(apiPath`${'backend'}/config/${'id'}`, 'backend', 'id'),
  canEdit: alias('editConnectionPath.canUpdate'),
  canDelete: alias('editConnectionPath.canDelete'),
  resetConnectionPath: lazyCapabilities(apiPath`${'backend'}/reset/${'id'}`, 'backend', 'id'),
  canReset: or('resetConnectionPath.canUpdate', 'resetConnectionPath.canCreate'),
  rotateRootPath: lazyCapabilities(apiPath`${'backend'}/rotate-root/${'id'}`, 'backend', 'id'),
  canRotateRoot: or('rotateRootPath.canUpdate', 'rotateRootPath.canCreate'),
  rolePath: lazyCapabilities(apiPath`${'backend'}/role/*`, 'backend'),
  staticRolePath: lazyCapabilities(apiPath`${'backend'}/static-role/*`, 'backend'),
  canAddRole: or('rolePath.canCreate', 'staticRolePath.canCreate'),
});
