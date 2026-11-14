// The only configuration the plug-in uses. scan.cjs passes it as overrideConfigFile, so ESLint
// never loads a configuration file, parser or plug-in from the scanned repository.
import security from 'eslint-plugin-security';
import tseslint from 'typescript-eslint';

const JAVASCRIPT = ['**/*.js', '**/*.jsx', '**/*.mjs', '**/*.cjs'];
const TYPESCRIPT = ['**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cts'];

export default [
  {
    files: ['**/*.jsx'],
    languageOptions: { parserOptions: { ecmaFeatures: { jsx: true } } },
  },
  {
    // Parsing only, without type information, so no tsconfig.json of the scanned
    // repository is read.
    files: TYPESCRIPT,
    languageOptions: { parser: tseslint.parser },
  },
  {
    ...security.configs.recommended,
    files: [...JAVASCRIPT, ...TYPESCRIPT],
  },
  {
    linterOptions: {
      reportUnusedDisableDirectives: 'off',
      reportUnusedInlineConfigs: 'off',
    },
  },
];
