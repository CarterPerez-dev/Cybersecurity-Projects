// ©AngelaMos | 2025
// stylelint.config.js

/** @type {import('stylelint').Config} */
export default {
  extends: ['stylelint-config-standard-scss', 'stylelint-config-prettier-scss'],
  rules: {
    'block-no-empty': true,
    'declaration-no-important': true,
    'color-no-invalid-hex': true,
    'property-no-unknown': true,
    'selector-pseudo-class-no-unknown': [
      true,
      {
        ignorePseudoClasses: ['global'],
      },
    ],

    'selector-class-pattern': [
      '^[a-z]([a-z0-9-]+)?(__[a-z0-9]([a-z0-9-]+)?)?(--[a-z0-9]([a-z0-9-]+)?)?$|^[a-z][a-zA-Z0-9]*$',
      {
        message:
          'Selector should be in BEM format (e.g., .block__element--modifier) or CSS Modules camelCase (e.g., .testButton)',
      },
    ],

    'value-keyword-case': [
      'lower',
      {
        camelCaseSvgKeywords: true,
        ignoreKeywords: [
          'BlinkMacSystemFont',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'Roboto',
          'Arial',
          'Helvetica',
          'Times',
          'Georgia',
          'Verdana',
          'Tahoma',
          'Trebuchet',
          'Impact',
          'Comic',
        ],
      },
    ],

    'property-no-vendor-prefix': [
      true,
      {
        ignoreProperties: ['text-size-adjust', 'appearance', 'backdrop-filter'],
      },
    ],
    'value-no-vendor-prefix': true,
    'selector-no-vendor-prefix': true,

    'property-no-deprecated': [
      true,
      {
        ignoreProperties: ['clip'],
      },
    ],

    'container-name-pattern': null,
    'layer-name-pattern': null,

    'scss/at-rule-no-unknown': true,
    'scss/declaration-nested-properties-no-divided-groups': true,
    'scss/dollar-variable-no-missing-interpolation': true,
    'scss/dollar-variable-empty-line-before': null,

    'declaration-empty-line-before': null,
    'custom-property-empty-line-before': null,

    'no-descending-specificity': null,

    'media-feature-name-no-unknown': [
      true,
      {
        ignoreMediaFeatureNames: ['map'],
      },
    ],

    'color-function-notation': null,
    'hue-degree-notation': null,
  },
  ignoreFiles: [
    'node_modules/**',
    'dist/**',
    'build/**',
    '**/*.js',
    '**/*.ts',
    '**/*.tsx',
  ],
  overrides: [
    {
      files: ['**/styles/_reset.scss', '**/styles/_fonts.scss'],
      rules: {
        'declaration-no-important': null,
        'scss/comment-no-empty': null,
      },
    },
  ],
}
