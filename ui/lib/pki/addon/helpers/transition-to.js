/**
 * Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
 * SPDX-License-Identifier: MPL-2.0
 */

import { inject as service } from '@ember/service';
import Helper from '@ember/component/helper';
import handleQueryParams from 'ember-router-helpers/utils/handle-query-params';

export default class TransitionToHelper extends Helper {
  @service('host-router') router;
  compute(_params) {
    return (maybeEvent) => {
      if (maybeEvent !== undefined && typeof maybeEvent.preventDefault === 'function') {
        maybeEvent.preventDefault();
      }
      return this.router.transitionTo(...handleQueryParams(_params));
    };
  }
}
