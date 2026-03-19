import { defaultConfig } from "@caido/eslint-config";

/** @type {import('eslint').Linter.Config } */
export default [
  {
    ignores: ["eslint.config.mjs", ".githooks/**", ".github/**", ".cursor/**"],
  },
  ...defaultConfig(),
  {
    files: ["packages/**/*.{ts,tsx,vue}"],
    rules: {
      "@typescript-eslint/no-restricted-types": [
        "error",
        {
          types: {
            null: {
              message:
                "Do not use `null` as a type. Use `undefined` instead.",
            },
          },
        },
      ],
    },
  },
];
