/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Component from '@glimmer/component';
import { tracked } from '@glimmer/tracking';

export default class PgpListComponent extends Component {
  @tracked listData = [];
  onDataUpdate = () => {};
  listLength = 0;

  constructor() {
    super(...arguments);
    let num = this.listLength;
    if (num) {
      num = parseInt(num, 10);
    }
    this.listData = this.newList(num);
  }

  didReceiveAttrs() {
    let list;
    if (!this.listLength) {
      this.listData = [];
      return;
    }
    if (this.listData.length === this.listLength) {
      return;
    }
    if (this.listLength < this.listData.length) {
      list = this.listData.slice(0, this.listLength);
    } else if (this.listLength > this.listData.length) {
      list = [...this.listData, ...this.newList(this.listLength - this.listData.length)];
    }
    this.listData = list || this.listData;
    this.onDataUpdate((list || this.listData).filter(Boolean).map((k) => k.value));
  }

  newList(length) {
    return Array(length || 0)
      .fill(null)
      .map(() => ({ value: '' }));
  }

// this should be in a .ts file probably
  actions: {
    setKey(index, key) {
      const { listData } = this;
      listData.splice(index, 1, key);
      this.onDataUpdate(listData.compact().map((k) => k.value));
    },
  },
});
