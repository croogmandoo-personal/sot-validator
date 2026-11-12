#!/usr/bin/env bash
set -euo pipefail

# 1. Validate factory config and scripts
python3 -m json.tool factory/config.json > /dev/null
python3 -m py_compile factory/bin/job factory/bin/gate factory/bin/route

# 2. Run your project's build, typecheck, linter, and test suite
if [ -d "src" ] && [ -n "$(find src -name '*.py' -print -quit)" ]; then
  find src -name '*.py' -exec python3 -m py_compile {} +
fi

# Parens required: without them, `test_*.py` matches the first -o branch with no
# action and this condition stays empty, so the gate never runs pytest.
if [ -d "tests" ] && [ -n "$(find tests \( -name 'test_*.py' -o -name '*_test.py' \) -print -quit)" ]; then
  python3 -m pytest
fi


