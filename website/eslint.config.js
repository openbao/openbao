import { defineConfig } from "eslint/config";
import docusaurus from "@docusaurus/eslint-plugin";
import eslintJs from "@eslint/js";
const { configs } = eslintJs;
import { FlatCompat } from "@eslint/eslintrc";
import importPlugin from "eslint-plugin-import";
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import globals from "globals";
import { fileURLToPath } from "url";
import path from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: configs.recommended,
    allConfig: configs.all
});

const sharedImportSettings = {
    "import/resolver": {
        node: {
            extensions: [".js", ".jsx", ".ts", ".tsx", ".css"],
            moduleDirectory: ["node_modules", "src"],
        },
    },
};

const sharedImportRules = {
    "import/no-unresolved": [2, {
        ignore: ["^@theme", "^@docusaurus", "^@site", "\\.css$"],
    }],
};

export default defineConfig([
    ...compat.extends("eslint:recommended", "plugin:@docusaurus/recommended").map(cfg => ({
        ...cfg,
        files: ["**/*.{js,jsx,ts,tsx}"],
    })),
    {
        files: ["**/*.{js,jsx}"],
        plugins: {
            "@docusaurus": docusaurus,
            "import": importPlugin,
        },
        languageOptions: {
            globals: { ...globals.browser },
        },
        settings: sharedImportSettings,
        rules: sharedImportRules,
    },
    {
        files: ["**/*.{ts,tsx}"],
        plugins: {
            "@docusaurus": docusaurus,
            "import": importPlugin,
            "@typescript-eslint": tsPlugin,
        },
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaFeatures: { jsx: true },
            },
            globals: {
                ...globals.browser,
                JSX: "readonly",
            },
        },
        settings: sharedImportSettings,
        rules: sharedImportRules,
    },
    {
        files: ["src/docusaurus-plugin-sidebar-json/**/*.ts"],
        languageOptions: {
            globals: { ...globals.node },
        },
    },
]);
