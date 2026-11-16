#!/usr/bin/env bash
# The local gate (run it in the pinned toolchain: tools/container.sh tools/gate.sh [JOB...]).
# Jobs, in order: format, build, test, fuzz, audit. Exit status 1 when any job fails; a summary of
# every job is printed at the end.
#   FUZZ_SECONDS   seconds per fuzz target (default 60)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
JOBS=("$@")
[[ ${#JOBS[@]} -gt 0 ]] || JOBS=(format build test fuzz audit)
FUZZ_SECONDS=${FUZZ_SECONDS:-60}
FUZZ_TARGETS=(tags headeronly verdicts)

restore() { dotnet restore MailAuth.slnx --locked-mode -v quiet; }
# Whitespace, code style and analyzer diagnostics at their configured severities (.editorconfig).
format() { restore && dotnet format MailAuth.slnx --no-restore --verify-no-changes -v quiet; }
# .NET analyzers (latest-recommended) and the trim/AOT analyzers (IsAotCompatible) with warnings as errors.
build() { restore && dotnet build MailAuth.slnx -c Release --no-restore -nologo -clp:NoSummary -warnaserror; }
test() {
  dotnet build tests/MailAuth.Tests/MailAuth.Tests.csproj -c Release --no-restore -nologo -v quiet -o artifacts/test \
    && dotnet artifacts/test/MailAuth.Tests.dll
}
fuzz() {
  local t rc=0
  rm -rf artifacts/fuzz/build
  for t in "${FUZZ_TARGETS[@]}"; do fuzz/run.sh "$t" "$FUZZ_SECONDS" || rc=1; done
  return $rc
}
audit() {
  restore || return 1
  dotnet list MailAuth.slnx package --vulnerable --include-transitive 2>&1 | tee artifacts/vulnerable.log
  ! grep -qE '^\s+>\s' artifacts/vulnerable.log
}

declare -A RESULT
fail=0
mkdir -p artifacts
for j in "${JOBS[@]}"; do
  echo "=== $j"
  start=$SECONDS
  if "$j"; then RESULT[$j]="PASS $((SECONDS - start))s"; else RESULT[$j]="FAIL $((SECONDS - start))s"; fail=1; fi
done
echo "=== summary"
for j in "${JOBS[@]}"; do echo "$j: ${RESULT[$j]}"; done
exit $fail
