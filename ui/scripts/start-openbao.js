/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

/* eslint-env node */
/* eslint-disable no-console */
/* eslint-disable no-process-exit */
/* eslint-disable n/no-extraneous-require */

var readline = require('readline');
const testHelper = require('./test-helper');

var output = '';
var unseal, root, written, initError;

async function processLines(input, eachLine = () => {}) {
  const rl = readline.createInterface({
    input,
    terminal: true,
  });
  for await (const line of rl) {
    eachLine(line);
  }
}

(async function () {
  try {
    const vault = testHelper.run(
      'bao',
      ['server', '-dev', '-dev-ha', '-dev-root-token-id=root', '-dev-listen-address=127.0.0.1:9200'],
      false
    );
    processLines(vault.stdout, function (line) {
      if (written) {
        output = null;
        return;
      }
      output = output + line;
      var unsealMatch = output.match(/Unseal Key: (.+)$/m);
      if (unsealMatch && !unseal) {
        unseal = [unsealMatch[1]];
      }
      var rootMatch = output.match(/Root Token: (.+)$/m);
      if (rootMatch && !root) {
        root = rootMatch[1];
      }
      var errorMatch = output.match(/Error initializing core: (.*)$/m);
      if (errorMatch) {
        initError = errorMatch[1];
      }
      if (root && unseal && !written) {
        testHelper.writeKeysFile(unseal, root);
        written = true;
        console.log('OPENBAO SERVER READY');
      } else if (initError) {
        console.log('OPENBAO SERVER START FAILED');
        process.exit(1);
      }
    });
    try {
      await testHelper.run('ember', ['test', ...process.argv.slice(2)]);
    } catch (error) {
      console.log(error);
      process.exit(1);
    } finally {
      process.exit(0);
    }
  } catch (error) {
    console.log(error);
    process.exit(1);
  }
})();
