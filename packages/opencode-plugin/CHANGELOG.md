# Changelog

## [0.4.0](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.3.1...opencode-plugin-v0.4.0) (2026-10-18)


### Features

* **adapters:** persist delivery cursors server-side ([84e61b7](https://github.com/phall1/blackbird/commit/84e61b7fe359387e7d74e069d4f77de52e8a5907))
* **blackbird:** add durable OpenCode push delivery ([d1ec6c3](https://github.com/phall1/blackbird/commit/d1ec6c3a7dc268b3968fc5e1e73ebe6397a45865))
* **blackbird:** support portable plugin project paths ([f627684](https://github.com/phall1/blackbird/commit/f6276843eae0df9a120a24bcd67c53a8f181202b))
* move harness delivery into native plugins ([b378ebc](https://github.com/phall1/blackbird/commit/b378ebc0b0890621805eb898d465fccf1d79665c))
* **opencode-plugin:** add native V2 Effect mailbox browser ([442086f](https://github.com/phall1/blackbird/commit/442086f50846d647f84f20b5f5d84203c0cbe972))
* **opencode-plugin:** report token usage to the observation plane ([eb2511c](https://github.com/phall1/blackbird/commit/eb2511c0e26d305913201e37518821b25bacf1d9))


### Bug Fixes

* **blackbird:** share push supervisor across projects ([c38ad2a](https://github.com/phall1/blackbird/commit/c38ad2ae82270a100109af60de97242b128ae739))
* load under the OpenCode V2 runtime, and unbreak CI ([#16](https://github.com/phall1/blackbird/issues/16)) ([eb74d16](https://github.com/phall1/blackbird/commit/eb74d16fcf376063b62a1d30a3688a5b48eb7eba))
* **opencode-plugin:** clear the high advisory blocking the release gate ([#17](https://github.com/phall1/blackbird/issues/17)) ([f103772](https://github.com/phall1/blackbird/commit/f103772e2c9657e14a524069f5e47726d4f4bd93))
* **opencode-plugin:** migrate to the stable API and stop spending a turn ([8fd6dbf](https://github.com/phall1/blackbird/commit/8fd6dbf9c2d6cec3feae47371e4b3e6aea8ef67b))
* **opencode-plugin:** refresh compatible dependencies for 0.3.1 ([#27](https://github.com/phall1/blackbird/issues/27)) ([f5efd44](https://github.com/phall1/blackbird/commit/f5efd441ad09ae7595c584c1a65941f8bc71d396))
* **opencode:** support stable host and packaged UI ([#25](https://github.com/phall1/blackbird/issues/25)) ([9d81c85](https://github.com/phall1/blackbird/commit/9d81c85cf2675c4a3272347874e99b4a01f9ff6f))
* **packages:** gate every plugin on the same audit level ([f8f6d64](https://github.com/phall1/blackbird/commit/f8f6d644aae81598f12573e0750f1d798df19f04))

## [0.3.1](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.3.0...opencode-plugin-v0.3.1) (2026-10-17)

### Bug Fixes

* **opencode-plugin:** refresh Zod and development tooling while retaining the OpenCode 2.0.32 host runtime pins and compiled Git-install entrypoints.

## [0.3.0](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.2.3...opencode-plugin-v0.3.0) (2026-09-09)


### Features

* **opencode-plugin:** add native V2 Effect mailbox browser ([442086f](https://github.com/phall1/blackbird/commit/442086f50846d647f84f20b5f5d84203c0cbe972))

## [0.2.3](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.2.2...opencode-plugin-v0.2.3) (2026-09-09)


### Bug Fixes

* **opencode-plugin:** clear the high advisory blocking the release gate ([#17](https://github.com/phall1/blackbird/issues/17)) ([f103772](https://github.com/phall1/blackbird/commit/f103772e2c9657e14a524069f5e47726d4f4bd93))

## [0.2.2](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.2.1...opencode-plugin-v0.2.2) (2026-09-09)


### Bug Fixes

* load under the OpenCode V2 runtime, and unbreak CI ([#16](https://github.com/phall1/blackbird/issues/16)) ([eb74d16](https://github.com/phall1/blackbird/commit/eb74d16fcf376063b62a1d30a3688a5b48eb7eba))

## [0.2.1](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.2.0...opencode-plugin-v0.2.1) (2026-09-02)


### Bug Fixes

* **packages:** gate every plugin on the same audit level ([f8f6d64](https://github.com/phall1/blackbird/commit/f8f6d644aae81598f12573e0750f1d798df19f04))

## [0.2.0](https://github.com/phall1/blackbird/compare/opencode-plugin-v0.1.3...opencode-plugin-v0.2.0) (2026-09-02)


### Features

* **adapters:** persist delivery cursors server-side ([84e61b7](https://github.com/phall1/blackbird/commit/84e61b7fe359387e7d74e069d4f77de52e8a5907))
* **opencode-plugin:** report token usage to the observation plane ([eb2511c](https://github.com/phall1/blackbird/commit/eb2511c0e26d305913201e37518821b25bacf1d9))


### Bug Fixes

* **opencode-plugin:** migrate to the stable API and stop spending a turn ([8fd6dbf](https://github.com/phall1/blackbird/commit/8fd6dbf9c2d6cec3feae47371e4b3e6aea8ef67b))
