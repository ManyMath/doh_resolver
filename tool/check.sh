#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dart pub get --no-example
dart format --output=none --set-exit-if-changed lib test tool example
dart analyze lib test tool example
dart test --reporter expanded
dart --packages=.dart_tool/package_config.json example/doh_resolver_example.dart
dart pub publish --dry-run
