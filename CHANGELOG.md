# Changelog

All notable changes to this project will be documented in this file.

## [3.3.0] - 2026-05-27

- Improve correctness in LMBCS encoding/decoding
- Add performance testing in LMBCS encoding/decoding
- Make LMBCS encoding/decoding more robust with LMBCS-20 (UTF-16) fallback
- Publish documentation to github pages

## [3.2.0] - 2026-05-25

- Improve LMBCS encoding/decoding and move to separate module

## [3.1.0] - 2026-05-24

- Add oxlint linter
- Replace prettier with oxfmt
- Upgrade to TypeScript 6
- Upgrade GitHub actions

## [3.0.0] - 2026-05-24

- Improve jsdoc for release

## [3.0.0-beta.1] - 2025-12-14

- Strict expiration validation by default
- Migrate from vitest to the native Node.Js test runner
- Minimum supported version of Node.Js is 20
- Improved api documentation

## [2.0.0] - 2024-02-18

- Add support for codepage 852 enabling eastern european characters in usernames
- Drop support for Node.js versions below 18
- Ecmascript only
- Migrate to vitest and node:test for testing

## [1.0.0] - 2019-07-19

### Added

- Dependency on prettier for consistent code formatting
- Pre-commit hook for pretty-quick
- Pre-push hook for automated tests
- Travis CI
- Code coverage reporting

### Changed

- Updated dependencies

### Removed

- Leading "I" on interfaces (that's a C#-ism)
- Devdependency on ts-node
