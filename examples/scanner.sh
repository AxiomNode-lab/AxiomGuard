#!/usr/bin/env bash
# Scan a repository, keep a reviewed baseline and produce SARIF for code scanning.
set -euo pipefail
cd "$(dirname "$0")/.."
CLI="node dist/cli.js"

$CLI rules
$CLI scan . --json --no-fail | head -20
$CLI scan . --sarif --output /tmp/axiomguard.sarif --no-fail && echo "wrote /tmp/axiomguard.sarif"
# First adoption: accept the current findings after review, then fail only on new ones.
# $CLI scan . --write-baseline .axiomguard-baseline.json
# $CLI scan .
