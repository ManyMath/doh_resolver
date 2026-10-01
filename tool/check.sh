#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dart pub get --no-example
dart format --output=none --set-exit-if-changed lib test tool
dart analyze lib test tool
dart test --reporter expanded
dart pub publish --dry-run
