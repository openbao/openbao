/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import Model from '@ember-data/model';
import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';
import { capability, addCapabilityRelationships } from 'vault/lib/capabilities';
import apiPath from 'vault/utils/api-path';

const MODEL_TYPE = 'test-form-model';

module('Unit | lib | attach capabilities', function (hooks) {
  setupTest(hooks);

  class TestModel extends Model {
    @capability(apiPath`update/${'id'}`)
    updatePath;
    @capability(apiPath`delete/${'id'}`)
    deletePath;
  }

  hooks.beforeEach(function () {
    this.owner.register('model:test', TestModel);
  });

  test('it creates relationships for capabilities', function (assert) {
    const relationships = this.owner
      .lookup('service:store')
      .getSchemaDefinitionService()
      .relationshipsDefinitionFor({ type: 'test' });

    let relationship = relationships['updatePath'];

    assert.strictEqual(relationship.key, 'updatePath', 'has updatePath relationship');
    assert.strictEqual(relationship.kind, 'belongsTo', 'kind of relationship is belongsTo');
    assert.strictEqual(relationship.type, 'capabilities', 'updatePath is a related capabilities model');

    relationship = TestModel.relationshipsByName.get('deletePath');
    assert.strictEqual(relationship.key, 'deletePath', 'has deletePath relationship');
    assert.strictEqual(relationship.kind, 'belongsTo', 'kind of relationship is belongsTo');
    assert.strictEqual(relationship.type, 'capabilities', 'deletePath is a related capabilities model');
  });

  test('it adds metadata to relatedCapabilities', function (assert) {
    const hasRelatedCapabilities =
      !!TestModel.relatedCapabilities && typeof TestModel.relatedCapabilities === 'object';
    assert.true(hasRelatedCapabilities, 'model class now has a relatedCapabilities object');
    assert.true(
      typeof TestModel.relatedCapabilities['updatePath'] === 'function',
      'relatedCapability for updatePath is function'
    );
    assert.true(
      typeof TestModel.relatedCapabilities['deletePath'] === 'function',
      'relatedCapability for updatePath is function'
    );
    assert.strictEqual(
      TestModel.relatedCapabilities['updatePath']({ id: 1 }),
      'update/1',
      'templateFn for updatePath is correct'
    );
    assert.strictEqual(
      TestModel.relatedCapabilities['deletePath']({ id: 1 }),
      'delete/1',
      'templateFn for deletePath is correct'
    );
  });

  // TODO: move this test to deserializer
  test('calling addCapabilityRelationships with single response JSON-API document adds expected relationships', function (assert) {
    const jsonAPIDocSingle = {
      data: {
        id: 'test',
        type: MODEL_TYPE,
        attributes: {},
        relationships: {},
      },
      included: [],
    };

    const expected = {
      data: {
        id: 'test',
        type: MODEL_TYPE,
        attributes: {},
        relationships: {
          updatePath: {
            data: {
              type: 'capabilities',
              id: 'update/test',
            },
          },
          deletePath: {
            data: {
              type: 'capabilities',
              id: 'delete/test',
            },
          },
        },
      },
      included: [],
    };

    addCapabilityRelationships(TestModel.relatedCapabilities, jsonAPIDocSingle);

    assert.strictEqual(
      Object.keys(jsonAPIDocSingle.data.relationships).length,
      2,
      'document now has 2 relationships'
    );
    assert.deepEqual(jsonAPIDocSingle, expected, 'has the exected new document structure');
  });

  test('calling static method with an arrary response JSON-API document adds expected relationships', function (assert) {
    const jsonAPIDocSingle = {
      data: [
        {
          id: 'test',
          type: MODEL_TYPE,
          attributes: {},
          relationships: {},
        },
        {
          id: 'foo',
          type: MODEL_TYPE,
          attributes: {},
          relationships: {},
        },
      ],
      included: [],
    };

    const expected = {
      data: [
        {
          id: 'test',
          type: MODEL_TYPE,
          attributes: {},
          relationships: {
            updatePath: {
              data: {
                type: 'capabilities',
                id: 'update/test',
              },
            },
            deletePath: {
              data: {
                type: 'capabilities',
                id: 'delete/test',
              },
            },
          },
        },
        {
          id: 'foo',
          type: MODEL_TYPE,
          attributes: {},
          relationships: {
            updatePath: {
              data: {
                type: 'capabilities',
                id: 'update/foo',
              },
            },
            deletePath: {
              data: {
                type: 'capabilities',
                id: 'delete/foo',
              },
            },
          },
        },
      ],
      included: [],
    };
    addCapabilityRelationships(TestModel.relatedCapabilities, jsonAPIDocSingle);
    assert.deepEqual(jsonAPIDocSingle, expected, 'has the exected new document structure');
  });
});
