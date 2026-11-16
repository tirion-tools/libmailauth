# Gate toolchain (tools/container.sh): the .NET 10 SDK image by digest (SDK 10.0.404, runtime 10.0.15, Ubuntu 24.04),
# clang 18 with libFuzzer for libfuzzer-dotnet, and the SharpFuzz instrumenter. Downloads are checked against their
# SHA-256 before use; apt packages are exact versions.
FROM mcr.microsoft.com/dotnet/sdk@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb
ARG SHARPFUZZ_VERSION=2.3.0
ARG SHARPFUZZ_SHA256=ffb1892f3787ff186364f4039965c9adeaca42a0dd994511295bf4ba8c5f5b03
ARG LIBFUZZER_DOTNET_VERSION=2025.05.02.0904
ARG LIBFUZZER_DOTNET_SHA256=5596fee3e0c84740e1f75f44834bb705b13bebc2df7b59b8302784423ae3db0d
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang-18=1:18.1.3-1ubuntu1 libclang-rt-18-dev=1:18.1.3-1ubuntu1 unzip=6.0-28ubuntu4.1 \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; mkdir /build; cd /build \
 && curl -fsSLo sharpfuzz.nupkg "https://api.nuget.org/v3-flatcontainer/sharpfuzz.commandline/${SHARPFUZZ_VERSION}/sharpfuzz.commandline.${SHARPFUZZ_VERSION}.nupkg" \
 && echo "${SHARPFUZZ_SHA256}  sharpfuzz.nupkg" | sha256sum -c - \
 && mkdir -p /opt/sharpfuzz && unzip -q sharpfuzz.nupkg 'tools/net10.0/any/*' -d /opt/sharpfuzz \
 && printf '#!/bin/sh\nexec dotnet /opt/sharpfuzz/tools/net10.0/any/SharpFuzz.CommandLine.dll "$@"\n' > /usr/local/bin/sharpfuzz \
 && chmod 0755 /usr/local/bin/sharpfuzz \
 && curl -fsSLo lfd.tar.gz "https://github.com/Metalnem/libfuzzer-dotnet/archive/refs/tags/v${LIBFUZZER_DOTNET_VERSION}.tar.gz" \
 && echo "${LIBFUZZER_DOTNET_SHA256}  lfd.tar.gz" | sha256sum -c - \
 && tar -xzf lfd.tar.gz \
 && clang-18 -Werror -O2 -fsanitize=fuzzer "libfuzzer-dotnet-${LIBFUZZER_DOTNET_VERSION}/libfuzzer-dotnet.cc" -o /usr/local/bin/libfuzzer-dotnet \
 && cd / && rm -rf /build
