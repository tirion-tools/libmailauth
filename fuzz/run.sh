#!/usr/bin/env bash
# Coverage-guided fuzz smoke of one MailAuth target (tools/gate.sh fuzz).
#
#   fuzz/run.sh TARGET SECONDS
#
# Builds the harness (JIT), copies it to artifacts/fuzz/TARGET/instrumented, instruments MailAuth.dll there with the
# pinned sharpfuzz tool, writes the seed corpus with the uninstrumented build (instrumented code needs libFuzzer's
# shared memory) and runs libfuzzer-dotnet for SECONDS with edge-coverage feedback. An exception escaping the harness
# is a crash: libFuzzer writes the input to artifacts/fuzz-findings/ and exits non-zero.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
target=${1:?target} secs=${2:?seconds}
build=artifacts/fuzz/build work=artifacts/fuzz/$target findings=artifacts/fuzz-findings
export MAILAUTH_FUZZ_TARGET=$target
if [[ ! -f $build/MailAuth.Fuzz.dll ]]; then
  dotnet build fuzz/MailAuth.Fuzz/MailAuth.Fuzz.csproj -c Release --no-restore -nologo -v quiet -o "$build"
fi
rm -rf "$work/instrumented" && mkdir -p "$work/corpus" "$findings"
cp -a "$build" "$work/instrumented"
sharpfuzz "$work/instrumented/MailAuth.dll"
dotnet "$build/MailAuth.Fuzz.dll" --seeds "$work/corpus"
exec libfuzzer-dotnet --target_path="$(command -v dotnet)" --target_arg="$work/instrumented/MailAuth.Fuzz.dll" \
  -max_total_time="$secs" -timeout=30 -rss_limit_mb=2048 -print_final_stats=1 "-artifact_prefix=$findings/$target-" "$work/corpus"
