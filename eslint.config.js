import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import importPlugin from "eslint-plugin-import"; // Import the plugin

export default [
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
    languageOptions: {
      globals: globals.browser,
    },
    // Integrate configurations from JS, TypeScript, and import plugin
    plugins: {
      import: importPlugin, // Register the import plugin
    },
    rules: {
      // Add recommended rules for the import plugin
      ...pluginJs.configs.recommended.rules,
      ...tseslint.configs.recommended.rules,
      "import/no-unresolved": "error", // Ensures that imported modules can be resolved
      "import/named": "error", // Ensures named imports match exported names
      "import/default": "error", // Ensures default exports exist and are imported correctly
      "import/no-extraneous-dependencies": "error", // Prevents importing packages not listed in package.json
      "import/order": [
        "error",
        {
          groups: [["builtin", "external", "internal"]],
          "newlines-between": "always",
        },
      ], // Enforces a specific order of import statements
      "import/no-duplicates": "error", // Prevents duplicate imports of the same module
    },
  },
];
