#!/usr/bin/env bash
set -euo pipefail

# Go to repo root (scripts/..)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Load .env if present
if [ -f .env ]; then
  # ignore commented lines
  export $(grep -v '^#' .env | xargs)
fi

# Lambda name – falls back if env var not set
FUNC_NAME="${WEEKLY_REPORT_LAMBDA:-fafo-weekly-audit-report}"
OUT_FILE="weekly_lambda_output.json"

echo "Invoking Lambda: $FUNC_NAME ..."
aws lambda invoke \
  --function-name "$FUNC_NAME" \
  --invocation-type RequestResponse \
  --log-type Tail \
  --payload '{}' \
  "$OUT_FILE"

echo
echo "Lambda response saved to: $OUT_FILE"
cat "$OUT_FILE"
echo
