import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  reactHooks.configs.flat["recommended-latest"],
  {
    languageOptions: { globals: globals.browser },
    rules: {
      // Logged text is attacker-controlled: never render it as HTML (spec section 10).
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Never render HTML from data; render text so React escapes it.",
        },
        {
          selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
          message: "Never write HTML from data.",
        },
      ],
      // The admin key lives in memory only (spec section 10).
      "no-restricted-globals": [
        "error",
        { name: "localStorage", message: "Do not persist anything; the admin key stays in memory." },
        { name: "sessionStorage", message: "Do not persist anything; the admin key stays in memory." },
      ],
    },
  },
);
