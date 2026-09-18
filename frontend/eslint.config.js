import js from "@eslint/js";
import globals from "globals";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";

export default [
  { ignores: ["dist/**", "node_modules/**"] },

  {
    files: ["src/**/*.{js,jsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: globals.browser,
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    settings: {
      react: { version: "18.3" },
      // jsx-a11y only inspects lowercase DOM elements, so <TableRow onClick>
      // escaped every interaction check. Mapping the shadcn primitives to the
      // element each one renders lets it see them.
      "jsx-a11y": {
        components: {
          TableRow: "tr",
          TableCell: "td",
          TableHead: "th",
          Button: "button",
          Input: "input",
          Label: "label",
          Textarea: "textarea",
          Badge: "span",
        },
      },
    },
    plugins: { react, "react-hooks": reactHooks, "jsx-a11y": jsxA11y },
    rules: {
      ...js.configs.recommended.rules,
      ...react.configs.recommended.rules,
      ...react.configs["jsx-runtime"].rules,
      // The two classic hook rules. The rest of eslint-plugin-react-hooks v7's
      // "recommended" set are React Compiler checks, and this app does not use
      // the compiler.
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      ...jsxA11y.configs.recommended.rules,

      // PropTypes are replaced by the API's own shapes; the project has none.
      "react/prop-types": "off",
      // An apostrophe in JSX text renders exactly as written; it is prose, not
      // markup. The characters that genuinely mean a JSX mistake stay forbidden.
      "react/no-unescaped-entities": ["error", { forbid: [">", "}"] }],
      // Leading-underscore names are deliberate "unused on purpose" markers.
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // A region that scrolls must be focusable, or its hidden content is
      // unreachable without a mouse — axe flags exactly that as
      // "scrollable-region-focusable". This rule otherwise forbids the tabIndex
      // that fixes it, so named group/region containers are allowed to take one.
      "jsx-a11y/no-noninteractive-tabindex": ["error", { tags: [], roles: ["tabpanel", "group", "region"] }],
    },
  },

  {
    // Playwright smoke test: runs in Node, not the browser.
    files: ["e2e/**/*.js", "*.config.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: { ...globals.node, ...globals.browser },
    },
    rules: { ...js.configs.recommended.rules },
  },
];
