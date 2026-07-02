/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint-disable ember/no-observers */
import { inject as service } from '@ember/service';
import { isArray } from '@ember/array';
import Helper from '@ember/component/helper';

const exact = (a, b) => a === b;
const startsWith = (a, b) => a.indexOf(b) === 0;

export default class IsActiveRoute extends Helper {
  @service('host-router') router;

  compute([routeName, model], { isExact }) {
    const router = this.router;
    const currentRoute = router.currentRouteName;
    let currentURL = router.currentURL;
    // if we have any query params we want to discard them
    currentURL = currentURL?.split('?')[0];
    const comparator = isExact ? exact : startsWith;
    if (!currentRoute) {
      return false;
    }
    if (isArray(routeName)) {
      return routeName.some((name) => comparator(currentRoute, name));
    } else if (model) {
      // slice off the rootURL from the generated route
      return comparator(currentURL, router.urlFor(routeName, model).slice(router.rootURL.length - 1));
    } else {
      return comparator(currentRoute, routeName);
    }
  }
}
