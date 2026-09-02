# Changelog

## [0.5.0](https://github.com/phall1/blackbird/compare/v0.4.1...v0.5.0) (2026-09-02)


### Features

* **adapters:** persist delivery cursors server-side ([84e61b7](https://github.com/phall1/blackbird/commit/84e61b7fe359387e7d74e069d4f77de52e8a5907))
* **cli:** check staged paths against other agents' reservations ([da4d32b](https://github.com/phall1/blackbird/commit/da4d32b9601c003eeb2d09088135c801baeff244))
* **cli:** report Claude Code token usage from the session transcript ([491e70e](https://github.com/phall1/blackbird/commit/491e70e982bfb51cfa25fcee4c60b2a56d6ef3e6))
* **cli:** ship backup and restore, and give doctor an opinion ([b01e508](https://github.com/phall1/blackbird/commit/b01e5086decb0d35edd8c270d7add7b8fce79387))
* **contracts:** give coordination failures typed recovery evidence ([8996c28](https://github.com/phall1/blackbird/commit/8996c286774a3eedb070848aff2125dbfbabae9b))
* **coordination:** make agent recovery actionable ([c5e4769](https://github.com/phall1/blackbird/commit/c5e4769b4651e2c6dafbee99581bafcf44acd775))
* **coordination:** make worktree-per-writer the default for parallel agents ([f17d7a9](https://github.com/phall1/blackbird/commit/f17d7a936857dd530979d24ccc55f4f4f29f31e8))
* **coordination:** observe Beads work references ([379f5f2](https://github.com/phall1/blackbird/commit/379f5f2d7504496299847044177fd34f91eda294))
* **coordination:** persist adapter delivery cursors ([b1f7afc](https://github.com/phall1/blackbird/commit/b1f7afcf12b19532b0420bc85e38d9a828dce1db))
* **delivery:** add shared command-hook adapter ([ca2805a](https://github.com/phall1/blackbird/commit/ca2805ad01d7ecce35bca6d961bf406631830d85))
* **http:** log the request id and the errors the transport discarded ([6b7ba41](https://github.com/phall1/blackbird/commit/6b7ba41d6dcb2ba82eecc8cedb2edcd94071b862))
* **mcp:** adopt eight agent-native tools ([e393e0a](https://github.com/phall1/blackbird/commit/e393e0a23776c83bfccc11d7a82b40dd1e1a3dee))
* **mcp:** return held state from registration and stop self-conflicting ([9ed41d0](https://github.com/phall1/blackbird/commit/9ed41d079b94d7a32128f156691a8434100b7222))
* **mcp:** stop registering the uncallable identity plane ([6ef6019](https://github.com/phall1/blackbird/commit/6ef60192b6f840429f3b767507c545ff97fb1a11))
* **ops:** expose lightweight daemon metrics ([58557a2](https://github.com/phall1/blackbird/commit/58557a20643464850fdf83bd0bfc60ee290d1568))
* **reservations:** add admin force release ([83d596a](https://github.com/phall1/blackbird/commit/83d596a43656d2a371c073f3578f4b0c338ed83a))
* **storage:** bound coordination journal retention ([efe32c8](https://github.com/phall1/blackbird/commit/efe32c8c3ef56be4b7c3d1f3f400902adae8f887))
* **storage:** remove the PostgreSQL backend ([5415049](https://github.com/phall1/blackbird/commit/541504939e94367d064e97e929292db3757a8ebe))
* **telemetry:** add the observation plane with a fail-open ingest sink ([77e440f](https://github.com/phall1/blackbird/commit/77e440ff96c07baa28ce34b409ea0d873ad539cd))
* **telemetry:** ingest observations over the local HTTP surface ([f51cd54](https://github.com/phall1/blackbird/commit/f51cd54689df6ce582a6d6efad0e6ef6b3172869))
* **telemetry:** report where tokens and time went ([6780ead](https://github.com/phall1/blackbird/commit/6780ead4d01952908d629788dfa8ed981a0a2eb1))


### Bug Fixes

* **cli:** add the backup command files that were never staged ([777de21](https://github.com/phall1/blackbird/commit/777de21f35725b8a9a599b6cb0562734cd017435))
* **coordination:** make journal events factual ([ada594c](https://github.com/phall1/blackbird/commit/ada594cc20b0cc9aaf3d233300f4655bd6e27d12))
* **install:** rotate the daemon logs so they stop growing forever ([f20ced8](https://github.com/phall1/blackbird/commit/f20ced803905d597ef8027093f83f01d936895bb))
* **install:** write daemon logs to files so blackbird logs works on Linux ([e666607](https://github.com/phall1/blackbird/commit/e66660763ccf1793a475dba7276c5959649854ed))
* let release-please tag the root package again ([0b53949](https://github.com/phall1/blackbird/commit/0b539492676f60b1ed2b700b0ef0f2173bdc86cd))
* **localsecurity:** return typed denials instead of retryable 500s ([a826bd1](https://github.com/phall1/blackbird/commit/a826bd1817d7d6e33a3ca71dd1a3980f4e657d42))
* **mcp:** name invalid reservation fields ([f5a7b0d](https://github.com/phall1/blackbird/commit/f5a7b0dbb872479e9dd3acc16cc47289375891a1))
* **mcp:** preserve claim conflict semantics ([b4600b7](https://github.com/phall1/blackbird/commit/b4600b7210635ef7e275301d6f75b234171d8afe))
* **ops:** surface swallowed failures ([df2a825](https://github.com/phall1/blackbird/commit/df2a825622accec84650010c84478d3d0fafcbe9))
* **runtime:** drain active ingress before storage ([78e5dad](https://github.com/phall1/blackbird/commit/78e5dad5d607bb551cdb3ad6fb7164404547d612))
* schedule no updater on a machine without Homebrew ([#8](https://github.com/phall1/blackbird/issues/8)) ([41e7940](https://github.com/phall1/blackbird/commit/41e7940f9ff91e85e59250452fc5b795dd16023d))
* **sqlite:** bound live WAL growth ([e5e0cf0](https://github.com/phall1/blackbird/commit/e5e0cf0000bd566ee5cf8e25d47f9c27230af5dd))
* **sqlite:** converge any known schema forward instead of one rung ([700cc49](https://github.com/phall1/blackbird/commit/700cc497ef91da22f7e72e2db5aa3d44e70e9aa4))
* **sqlite:** make lease contention legible and reap what expires ([da16bed](https://github.com/phall1/blackbird/commit/da16bed7dfd9fc9edefa2c8697ea305ae0357262))
* **sqlite:** verify the reader is read-only instead of inferring it ([a9a2e39](https://github.com/phall1/blackbird/commit/a9a2e3904530d1792e37934df0595ee00668c9b3))


### Performance

* **mcp:** omit redundant coordination output schemas ([c90045f](https://github.com/phall1/blackbird/commit/c90045f84858e39df75798c88fdc4b4b80f65ce8))
* **sqlite:** size read pool from CPU count ([2ed57d9](https://github.com/phall1/blackbird/commit/2ed57d90dadac588d22376d8e4365fca5fc590d7))

## [0.4.1](https://github.com/phall1/blackbird/compare/v0.4.0...v0.4.1) (2026-08-16)


### Bug Fixes

* point the make daemon target at the 0.4.0 argv ([e7f1a08](https://github.com/phall1/blackbird/commit/e7f1a083a2da219c161517fcb1dc3b5967bce19f))
* repair the work-plane command ingress ([#4](https://github.com/phall1/blackbird/issues/4)) ([c39de56](https://github.com/phall1/blackbird/commit/c39de568c3251e86bc2bc4f7fa348faf02a5fa5d))

## [0.4.0](https://github.com/phall1/blackbird/compare/v0.3.0...v0.4.0) (2026-08-15)


### Features

* add a first-class command line surface ([70d13e7](https://github.com/phall1/blackbird/commit/70d13e7145ea34969cc8d385271572e8e9e277b8))
* add a first-class command line surface ([#3](https://github.com/phall1/blackbird/issues/3)) ([c46464c](https://github.com/phall1/blackbird/commit/c46464c7e7a16ed5bdfb2271bab45b1294290f9f))
