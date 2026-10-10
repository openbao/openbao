/**
 * Copyright (c) OpenBao a Series of LF Projects, LLC
 * SPDX-License-Identifier: MPL-2.0
 */

import Modifier from 'ember-modifier';
import { capabilities, setModifierManager } from '@ember/modifier';
import { destroy } from '@ember/destroyable';

export default class InvokeModifier extends Modifier {
  modify(element, positional, named) {
    const method = positional[0];
    const args = positional.slice(1);
    const onUpdate = named.onUpdate;

    // Establish autotracking based on onUpdate:
    // - No onUpdate: don't track anything, modify runs only on insert
    // - onUpdate with deps: access deps to track them
    // - onUpdate=true: track named args object (new each render) to run on every update
    if (onUpdate !== undefined && onUpdate !== false) {
      if (onUpdate === true) {
        void named;
      } else if (Array.isArray(onUpdate)) {
        onUpdate.forEach((dep) => void dep);
      } else {
        void onUpdate;
      }
    }

    method(element, args, named);
  }
}

// Use a custom modifier manager with disableAutoTracking: true to match
// the behavior of did-insert/did-update (they don't track the callback's internals)
function installElement(state, element) {
  const installedState = state;
  installedState.element = element;
  return installedState;
}

class InvokeModifierManager {
  // 3.22 = modern modifier capabilities (Ember 3.22+)
  // disableAutoTracking: matches did-insert/did-update (don't track callback internals)
  capabilities = capabilities('3.22', { disableAutoTracking: true });

  constructor(owner) {
    this.owner = owner;
  }

  createModifier(modifierClass, args) {
    const instance = new modifierClass(this.owner, args);
    return { instance, element: null };
  }

  installModifier(createdState, element, args) {
    const state = installElement(createdState, element);
    state.instance.modify(element, args.positional, args.named);
  }

  updateModifier(state, args) {
    state.instance.modify(state.element, args.positional, args.named);
  }

  destroyModifier({ instance }) {
    destroy(instance);
  }
}

setModifierManager((owner) => new InvokeModifierManager(owner), InvokeModifier);
