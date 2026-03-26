/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';
import { action } from '@ember/object';
import { inject as service } from '@ember/service';
import { task } from 'ember-concurrency';
import handleHasManySelection from 'core/utils/search-select-has-many';

/**
 * @module MfaLoginEnforcementForm
 * MfaLoginEnforcementForm components are used to create and edit login enforcements
 *
 * @example
 * ```js
 * <MfaLoginEnforcementForm @model={{this.model}} @isInline={{false}} @onSave={{this.onSave}} @onClose={{this.onClose}} />
 * ```
 * @callback onSave
 * @callback onClose
 * @param {Object} model - login enforcement model
 * @param {Object} [isInline] - toggles inline display of form -- method selector and actions are hidden and should be handled externally
 * @param {Object} [modelErrors] - model validations state object if handling actions externally when displaying inline
 * @param {onSave} [onSave] - triggered on save success
 * @param {onClose} [onClose] - triggered on cancel
 */

export default class MfaLoginEnforcementForm extends Component {
  @service store;
  @service flashMessages;

  targetTypes = [
    { label: 'Authentication mount', type: 'accessor', key: 'auth_method_accessors' },
    { label: 'Authentication method', type: 'method', key: 'auth_method_types' },
    { label: 'Group', type: 'identity/group', key: 'identity_groups' },
    { label: 'Entity', type: 'identity/entity', key: 'identity_entities' },
  ];
  searchSelectOptions = null;

  @tracked name;
  @tracked targets = [];
  @tracked selectedTargetType = 'accessor';
  @tracked selectedTargetValue = null;
  @tracked searchSelect = {
    options: [],
    selected: [],
  };
  @tracked authMethods = [];
  @tracked modelErrors;

  constructor() {
    super(...arguments);
    // aggregate different target array properties on model into flat list
    this.flattenTargets();
    // eagerly fetch identity groups and entities for use as search select options
    this.resetTargetState();
    // only auth method types that have mounts can be selected as targets -- fetch from sys/auth and map by type
    this.fetchAuthMethods();
  }

  async flattenTargets() {
    for (const { label, key } of this.targetTypes) {
      const targetArray = await this.args.model[key];
      const targets = targetArray.map((value) => ({ label, key, value }));
      this.targets = [...this.targets, ...targets];
    }
  }
  async resetTargetState() {
    this.selectedTargetValue = null;
    const options = this.searchSelectOptions || {};
    if (!this.searchSelectOptions) {
      const types = ['identity/group', 'identity/entity'];
      for (const type of types) {
        try {
          const query = await this.store.query(type, {});
          options[type] = [...query];
        } catch {
          options[type] = [];
        }
      }
      this.searchSelectOptions = options;
    }
    if (this.selectedTargetType.includes('identity')) {
      this.searchSelect = {
        selected: [],
        options: [...options[this.selectedTargetType]],
      };
    }
  }
  async fetchAuthMethods() {
    const query = await this.store.findAll('auth-method');
    const mounts = [...query];
    this.authMethods = mounts.map((x) => x.type);
  }

  get selectedTarget() {
    return this.targetTypes.find((x) => x.type === this.selectedTargetType);
  }
  get errors() {
    return this.args.modelErrors || this.modelErrors;
  }

  @task
  *save() {
    this.modelErrors = {};
    // check validity state first and abort if invalid
    const { isValid, state } = this.args.model.validate();
    if (!isValid) {
      this.modelErrors = state;
    } else {
      try {
        yield this.args.model.save();
        this.args.onSave();
      } catch (error) {
        const message = error.errors ? error.errors.join('. ') : error.message;
        this.flashMessages.danger(message);
      }
    }
  }

  @action
  async onMethodChange(selectedIds) {
    const methods = await this.args.model.mfa_methods;
    handleHasManySelection(selectedIds, methods, this.store, 'mfa-method');
  }

  @action
  onTargetSelect(type) {
    this.selectedTargetType = type;
    this.resetTargetState();
  }
  @action
  setTargetValue(selected) {
    const { type } = this.selectedTarget;
    if (type.includes('identity')) {
      // for identity groups and entities grab model from store as value
      this.selectedTargetValue = this.store.peekRecord(type, selected[0]);
    } else {
      this.selectedTargetValue = selected;
    }
  }
  @action
  async addTarget() {
    const { label, key } = this.selectedTarget;
    const value = this.selectedTargetValue;
    if (!this.targets.includes({ label, value, key })) {
      this.targets = [...this.targets, { label, value, key }];
    }
    // add target to appropriate model property
    const collection = await this.args.model[key];
    if (!collection.includes(value)) {
      collection.push(value);
    }
    this.selectedTargetValue = null;
    this.resetTargetState();
  }
  @action
  async removeTarget(target) {
    this.targets = this.targets.filter((t) => t !== target);
    // remove target from appropriate model property
    const collection = await this.args.model[target.key];
    const valIdx = collection.indexOf(target.value);
    if (valIdx !== -1) {
      collection.splice(valIdx, 1);
    }
  }
  @action
  cancel() {
    // revert model changes
    this.args.model.rollbackAttributes();
    this.args.onClose();
  }
}
