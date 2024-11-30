/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { not } from '@ember/object/computed';
import { inject as service } from '@ember/service';
import Component from '@ember/component';
import { computed } from '@ember/object';
import { FEATURE_MACHINE_TIME } from 'vault/helpers/wizard-constants';

export default Component.extend({
  wizard: service(),
  permissions: service(),

  init() {
    this._super(...arguments);
    this.maybeHideFeatures();
  },

  maybeHideFeatures() {
    const features = this.allFeatures;
    features.forEach((feat) => {
      feat.disabled = this.doesNotHavePermission(feat.requiredPermissions);
    });
  },

  doesNotHavePermission(requiredPermissions) {
    // requiredPermissions is an object of paths and capabilities defined within allFeatures.
    // the expected shape is:
    // {
    //   'example/path': ['capability'],
    //   'second/example/path': ['update', 'sudo'],
    // }
    return !Object.keys(requiredPermissions).every((path) => {
      return this.permissions.hasPermission(path, requiredPermissions[path]);
    });
  },

  estimatedTime: computed('selectedFeatures', function () {
    let time = 0;
    for (const feature of Object.keys(FEATURE_MACHINE_TIME)) {
      if (this.selectedFeatures.includes(feature)) {
        time += FEATURE_MACHINE_TIME[feature];
      }
    }
    return time;
  }),
  selectProgress: computed('selectedFeatures', function () {
    let bar = this.selectedFeatures.map((feature) => {
      return { style: 'width:0%;', completed: false, showIcon: true, feature: feature };
    });
    if (bar.length === 0) {
      bar = [{ style: 'width:0%;', showIcon: false }];
    }
    return bar;
  }),
  allFeatures: computed(function () {
    return [
      {
        key: 'secrets',
        name: 'Secrets',
        steps: ['Enabling a Secrets Engine', 'Adding a secret'],
        selected: false,
        show: true,
        disabled: false,
        requiredPermissions: {
          'sys/mounts/example': ['update'],
        },
      },
      {
        key: 'authentication',
        name: 'Authentication',
        steps: ['Enabling an Auth Method', 'Managing your Auth Method'],
        selected: false,
        show: true,
        disabled: false,
        requiredPermissions: {
          'sys/auth': ['read'],
          'sys/auth/foo': ['update', 'sudo'],
        },
      },
      {
        key: 'policies',
        name: 'Policies',
        steps: [
          'Choosing a policy type',
          'Creating a policy',
          'Deleting your policy',
          'Other types of policies',
        ],
        selected: false,
        show: true,
        disabled: false,
        requiredPermissions: {
          'sys/policies/acl': ['list'],
        },
      },
      {
        key: 'tools',
        name: 'Tools',
        steps: ['Wrapping data', 'Lookup wrapped data', 'Rewrapping your data', 'Unwrapping your data'],
        selected: false,
        show: true,
        disabled: false,
        requiredPermissions: {
          'sys/wrapping/wrap': ['update'],
          'sys/wrapping/lookup': ['update'],
          'sys/wrapping/unwrap': ['update'],
          'sys/wrapping/rewrap': ['update'],
        },
      },
    ];
  }),

  selectedFeatures: computed('allFeatures.@each.selected', function () {
    return this.allFeatures.filterBy('selected').mapBy('key');
  }),

  cannotStartWizard: not('selectedFeatures.length'),

  actions: {
    saveFeatures() {
      const wizard = this.wizard;
      wizard.saveFeatures(this.selectedFeatures);
      wizard.transitionTutorialMachine('active.select', 'CONTINUE');
    },
  },
});
