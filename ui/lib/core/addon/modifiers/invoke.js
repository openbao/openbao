/**
 * Copyright (c) OpenBao a Series of LF Projects, LLC
 * SPDX-License-Identifier: MPL-2.0
 */

import { capabilities, setModifierManager } from '@ember/modifier';
import { destroy } from '@ember/destroyable';

/**
 * The `invoke` modifier calls a component method on element insertion and optionally on updates.
 * Matches the behavior of `did-insert`/`did-update` from @ember/render-modifiers.
 *
 * Usage:
 *   {{invoke this.methodName arg1 arg2}}                            // calls on insert only
 *   {{invoke this.methodName arg1 arg2 onUpdate=(array dep1 dep2)}} // calls on insert and when deps change
 *   {{invoke this.methodName arg1 arg2 onUpdate=true}}              // calls on every update
 *
 * The method receives the element as the first argument, followed by the positional args array,
 * then the named args object (matching @ember/render-modifiers behavior).
 *
 * @param {Function} positional[0] - The method to invoke (bound to component)
 * @param {...any} positional[1...] - Arguments to pass as an array to the method after the element
 * @param {Array|boolean} [named.onUpdate] - Dependencies to watch for updates, or true for all updates
 */
export default class InvokeModifier {
  lastDepsKey = null;

  constructor(owner, args) {
    this._owner = owner;
    this._args = args;
  }

  modify(element, positional, named) {
    const method = positional[0];
    const args = positional.slice(1);
    const onUpdate = named.onUpdate;

    // Check if we should run on update
    if (onUpdate !== undefined && onUpdate !== false) {
      // Create a plain array copy to avoid tracking the template's tracked array
      const deps = onUpdate === true ? [true] : Array.isArray(onUpdate) ? [...onUpdate] : [onUpdate];
      const depsKey = this.depsToKey(deps);
      const depsChanged = this.lastDepsKey === null || depsKey !== this.lastDepsKey;

      if (depsChanged) {
        this.lastDepsKey = depsKey;
        method(element, args, named);
        return;
      }
    }

    // Only run on insert (first time)
    if (this.lastDepsKey === null) {
      const deps =
        onUpdate === true
          ? [true]
          : Array.isArray(onUpdate)
            ? [...onUpdate]
            : onUpdate !== undefined
              ? [onUpdate]
              : null;
      this.lastDepsKey = deps ? this.depsToKey(deps) : null;
      method(element, args, named);
    }
  }

  depsToKey(deps) {
    // Convert deps array to a string key for comparison, avoiding tracked array issues
    return deps.map((d) => (d === true ? '*' : String(d))).join('|');
  }
}

function installElement(state, element) {
  const installedState = state;
  installedState.element = element;
  return installedState;
}

class InvokeModifierManager {
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
