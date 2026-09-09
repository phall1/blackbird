import eslint from "@eslint/js"
import tseslint from "typescript-eslint"

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/no-confusing-void-expression": "off",
    },
  },
  {
    files: ["src/{index,effect-delivery,mail-reader,rpc}.ts", "src/*.tsx"],
    rules: {
      complexity: ["error", 10],
      "max-depth": ["error", 3],
    },
  },
  {
    files: ["test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-empty-function": "off",
      "@typescript-eslint/require-await": "off",
    },
  },
)
