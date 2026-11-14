'use strict';
// Lints $SIEVE_SRC with the plug-in's own configuration and writes results.sarif and
// scan-info.json to $SIEVE_OUT. Exits with 0 after a scan, 3 when there was no JavaScript or
// TypeScript file to lint, and 1 when ESLint fails.
//
// This file is CommonJS because the SARIF formatter reads ESLint's version through
// require.main, which an ES module entry point doesn't set.

const fs = require('node:fs');
const path = require('node:path');
const { ESLint } = require('eslint');
const formatSarif = require('@microsoft/eslint-formatter-sarif');

const NOTHING_TO_SCAN = 3;

async function main() {
  const src = process.env.SIEVE_SRC;
  const out = process.env.SIEVE_OUT;
  const eslint = new ESLint({
    cwd: src,
    overrideConfigFile: path.join(__dirname, 'eslint.config.mjs'),
    // The same as --no-inline-config: eslint-disable comments in the scanned code are ignored.
    allowInlineConfig: false,
    errorOnUnmatchedPattern: false,
    warnIgnored: false,
  });
  const results = await eslint.lintFiles(['.']);
  if (results.length === 0) {
    console.error('no JavaScript or TypeScript files to lint');
    return NOTHING_TO_SCAN;
  }

  // The formatter is loaded from the plug-in's own node_modules, not through
  // eslint.loadFormatter(), which would look for it in the scanned repository.
  const sarif = formatSarif(results, {
    cwd: src,
    rulesMeta: eslint.getRulesMetaForResults(results),
  });
  fs.writeFileSync(path.join(out, 'results.sarif'), sarif);
  fs.writeFileSync(
    path.join(out, 'scan-info.json'),
    JSON.stringify({ files_scanned: results.length }),
  );

  // A file that can't be parsed is counted as scanned but has no results. The formatter puts
  // the parse error under invocations, and the log names the file.
  const unparsed = results.filter((result) => result.messages.some((m) => m.fatal));
  for (const result of unparsed) {
    const error = result.messages.find((m) => m.fatal);
    const file = path.relative(src, result.filePath);
    console.error(`could not parse ${file}:${error.line}: ${error.message}`);
  }
  const count = results.reduce((sum, result) => sum + result.messages.length, 0);
  console.error(
    `ESLint ${ESLint.version} linted ${results.length} files, ${count} messages, ` +
      `${unparsed.length} files could not be parsed`,
  );
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error) => {
    console.error(error);
    process.exit(1);
  },
);
