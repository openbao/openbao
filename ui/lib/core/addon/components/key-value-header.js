/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@glimmer/component';
import utils from 'vault/lib/key-utils';
import { encodePath } from 'vault/utils/path-encoding-helpers';

/**
 * @module KeyValueHeader
 * KeyValueHeader components show breadcrumbs for secret engines.
 *
 * @example
 * ```js
 <KeyValueHeader @path="vault.cluster.secrets.backend.show" @mode={{this.mode}} @root={{@root}}/>
 * ```
 * @param {string} [mode=null] - Used to set the currentPath.
 * @param {string} [baseKey=null] - Used to generate the path backward.
 * @param {string} [path=null] - The fallback path.
 * @param {string} [root=null] - Used to set the secretPath.
 * @param {boolean} [showCurrent=true] - Boolean to show the second part of the breadcrumb, ex: the secret's name.
 * @param {boolean} [linkToPaths=true] - If true link to the path.
 * @param {boolean} [isEngine=false] - Change the LinkTo if the path is coming from an engine.
 */

export default class KeyValueHeader extends Component {
  get showCurrent() {
    return this.args.showCurrent || true;
  }

  get linkToPaths() {
    return this.args.linkToPaths || true;
  }

  stripTrailingSlash(str) {
    return str[str.length - 1] === '/' ? str.slice(0, -1) : str;
  }

  get currentPath() {
    if (!this.args.mode || this.showCurrent === false) {
      return this.args.path;
    }
    return `vault.cluster.secrets.backend.${this.args.mode}`;
  }

  // Supply the breadcrumb models explicitly so the router doesn't have to
  // infer them from its (possibly mid-transition) state: the leading dynamic
  // segment comes from the root crumb, the leaf model from the crumb itself.
  crumbModels(crumb) {
    const rootModel = this.args.root?.model;
    const model = crumb.model;
    if (rootModel !== undefined && rootModel !== null && rootModel !== model) {
      return [rootModel, model];
    }
    return model !== undefined && model !== null ? [model] : [];
  }

  get secretPath() {
    const crumbs = [];
    const root = this.args.root;
    const baseKey = this.args.baseKey?.display || this.args.baseKey?.id;
    const baseKeyModel = encodePath(this.args.baseKey?.id);

    if (root) {
      crumbs.push({ ...root, models: this.crumbModels(root) });
    }

    if (!baseKey) {
      return crumbs;
    }

    const path = this.args.path;
    const currentPath = this.currentPath;
    const showCurrent = this.showCurrent;
    const ancestors = utils.ancestorKeysForKey(baseKey);
    const parts = utils.keyPartsForKey(baseKey);
    if (ancestors.length === 0) {
      crumbs.push({
        label: baseKey,
        text: this.stripTrailingSlash(baseKey),
        path: currentPath,
        model: baseKeyModel,
        models: this.crumbModels({ model: baseKeyModel }),
      });

      if (!showCurrent) {
        crumbs.pop();
      }

      return crumbs;
    }

    ancestors.forEach((ancestor, index) => {
      crumbs.push({
        label: parts[index],
        text: this.stripTrailingSlash(parts[index]),
        path: path,
        model: encodePath(ancestor),
        models: this.crumbModels({ model: encodePath(ancestor) }),
      });
    });

    crumbs.push({
      label: utils.keyWithoutParentKey(baseKey),
      text: this.stripTrailingSlash(utils.keyWithoutParentKey(baseKey)),
      path: currentPath,
      model: baseKeyModel,
      models: this.crumbModels({ model: baseKeyModel }),
    });

    if (!showCurrent) {
      crumbs.pop();
    }

    return crumbs;
  }
}
