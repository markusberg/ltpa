# Changelog

All notable changes to this project will be documented in this file.

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
