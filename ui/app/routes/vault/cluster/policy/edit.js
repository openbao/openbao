/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import ShowRoute from './show';

export default ShowRoute.extend({
  actions: {
    willTransition(transition) {
      const model = this.currentModel;
      if (!model) {
        return true;
      }
      if (model.hasDirtyAttributes) {
        if (
          window.confirm(
            'You have unsaved changes. Navigating away will discard these changes. Are you sure you want to discard your changes?'
          )
        ) {
          return true;
        } else {
          transition.abort();
          return false;
        }
      }
      return true;
    },
  },
});
