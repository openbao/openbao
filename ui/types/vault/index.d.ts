/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Ember from 'ember';

declare global {
  // Prevents ESLint from "fixing" this via its auto-fix to turn it into a type
  // alias (e.g. after running any Ember CLI generator)
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface Array<T> extends Ember.ArrayPrototypeExtensions<T> {}
  // interface Function extends Ember.FunctionPrototypeExtensions {}
}

export {};
