# PQC Reproducibility Guide

This document describes how to reproduce the build and fuzzing setup used for the PQC extension of CryptoFuzz. The extension focuses on ML-KEM and ML-DSA and includes support for PQC operation modelling, repository registration, structured mutation, differential execution, and backend integration for selected cryptographic libraries.

## Notes on Reproducibility

The fuzzing campaigns use fixed algorithm filters, a fixed seed, a fixed RSS limit, and a minimum module count of two to support differential comparison.

The corpus paths and crash-output directories can be changed, but the selected operations and parameter sets should remain the same when reproducing the thesis experiments.

For full campaign runs, use the same runtime duration, number of rounds, workers, jobs, RSS limit, and corpus setup described in the thesis methodology chapter.

## Scope

This repository is a research prototype developed for thesis evaluation. It focuses on ML-KEM and ML-DSA support in CryptoFuzz and was tested with liboqs, OpenSSL, and Botan backends.

## Status

The implementation is intended for research and reproducibility purposes. It should not be treated as production cryptographic software.
---

**Note**: The commands below assume that all repositories are placed under `$WORKDIR`. You may set this variable to any directory on your system.

## 1. Workspace Setup

```bash
export WORKDIR="$HOME/pqc-fuzzing"

export CRYPTOFUZZ_DIR="$WORKDIR/cryptofuzz-pqc"
export LIBOQS_DIR="$WORKDIR/liboqs"
export OPENSSL_DIR="$WORKDIR/openssl"
export BOTAN_DIR="$WORKDIR/botan"

mkdir -p "$WORKDIR"
```

Expected directory layout:

```bash
$WORKDIR/
├── cryptofuzz-pqc/
├── liboqs/
├── openssl/
└── botan/
```

Clone this repository into $CRYPTOFUZZ_DIR:

```bash
cd "$WORKDIR"

git clone https://github.com/<#username>/#repo-name>.git "$CRYPTOFUZZ_DIR"
```

## 2. Required Tools

Install the main build dependencies:

```bash
sudo apt update
sudo apt install -y \
  git \
  cmake \
  ninja-build \
  make \
  python3 \
  clang \
  lld \
  pkg-config
```

Clang is required because CryptoFuzz uses libFuzzer and sanitizer instrumentation.

## 3. Common Build Flags

The backend libraries should be built with sanitizer-compatible flags so they can be linked into the final fuzzing binary.

```bash
export CC=clang
export CXX=clang++

export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -O2 -g"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -D_GLIBCXX_DEBUG -O2 -g"
```

The fuzzer-no-link option instruments dependency libraries without linking them directly to the libFuzzer runtime. The final CryptoFuzz binary is linked with libFuzzer later.

---

## 4. Build liboqs

cd "$WORKDIR"

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_DIR"
cd "$LIBOQS_DIR"

mkdir -p build
cd build

cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DOQS_USE_OPENSSL=OFF \
  ..

ninja -j"$(nproc)"

```

Export the liboqs paths:

```bash
export LIBOQS_A_PATH="$LIBOQS_DIR/build/lib/liboqs.a"
export LIBOQS_INCLUDE_PATH="$LIBOQS_DIR/build/include"
```

## 5. Build OpenSSL

```bash
cd "$WORKDIR"

git clone --depth 1 https://github.com/openssl/openssl.git "$OPENSSL_DIR"
cd "$OPENSSL_DIR"

./Configure linux-x86_64 \
  no-shared \
  no-asm \
  -static \
  -fPIC \
  --prefix="$OPENSSL_DIR/build" \
  $CFLAGS

make -j"$(nproc)"
make install_sw
```

Export the OpenSSL paths:

```bash
export OPENSSL_A_PATH="$OPENSSL_DIR/build/lib64/libcrypto.a"
export OPENSSL_INCLUDE_PATH="$OPENSSL_DIR/build/include"
```

Depending on the local OpenSSL build, the static library may be located under build/lib/libcrypto.a instead of build/lib64/libcrypto.a.


## 6. Build Botan

```bash
cd "$WORKDIR"

git clone --depth 1 https://github.com/randombit/botan.git "$BOTAN_DIR"
cd "$BOTAN_DIR"

python3 configure.py \
  --cc=clang \
  --cc-bin=clang++ \
  --build-targets=static \
  --disable-modules=locking_allocator,x509 \
  --enable-modules=ml_kem,ml_dsa \
  --with-build-dir=build \
  --extra-cxxflags="$CXXFLAGS"

make -C build/build -j"$(nproc)"

```

Export the Botan paths:

```bash
export LIBBOTAN_A_PATH="$BOTAN_DIR/build/build/libbotan-3.a"
export BOTAN_INCLUDE_PATH="$BOTAN_DIR/build/build/include/public"
```

---

## 7. Generate CryptoFuzz Repository Files

Before building CryptoFuzz, generate the repository lookup files:

```bash
cd "$CRYPTOFUZZ_DIR"

./gen_repository.py

```

This step produces generated registry files used by the repository subsystem. The build will fail if these files are missing. An example message:

```cmd
include/cryptofuzz/repository.h:23:10: fatal error: ../../repository_tbl.h: No such file or directory
   23 | #include "../../repository_tbl.h"
      |          ^~~~~~~~~~~~~~~~~~~~~~~~
```

## 8. Build CryptoFuzz Modules

Build the backend modules that should participate in differential fuzzing.

**liboqs module**

```bash

cd "$CRYPTOFUZZ_DIR/modules/liboqs"

make clean
make -j"$(nproc)"
```

**OpenSSL module**

```bash
cd "$CRYPTOFUZZ_DIR/modules/openssl"

make clean
make -j"$(nproc)"
```

**Botan module**

```bash
cd "$CRYPTOFUZZ_DIR/modules/botan"

make clean
make -j"$(nproc)"
```

## 9. Build the CryptoFuzz Binary

From the root of the CryptoFuzz repository:

```bash
cd "$CRYPTOFUZZ_DIR"

make clean

CXX=clang++ \
CXXFLAGS="-fsanitize=address,undefined -O2 -g -D_GLIBCXX_DEBUG -DCRYPTOFUZZ_LIBOQS" \
make -j"$(nproc)"
```

Adjust the compile-time flags depending on the modules included in the local build.


## 10. Prepare Corpus and Crash Directories

Create directories for the seed corpus and crash artifacts before starting fuzzing. The exact paths can be changed to match the local system layout.

```bash
mkdir -p "$CRYPTOFUZZ_DIR/corpus/kem"
mkdir -p "$CRYPTOFUZZ_DIR/corpus/pqsign"

mkdir -p "$CRYPTOFUZZ_DIR/crashes/kem"
mkdir -p "$CRYPTOFUZZ_DIR/crashes/pqsign"
```

In the commands below, replace the corpus and crash paths with the directories used in the local setup if they differ.


## 11. Generate Synthetic Corpus Inputs

Generate structured seed corpus files for ML-KEM and ML-DSA. These inputs provide initial operation layouts and boundary-oriented values before fuzzing begins.

```bash
cd "$CRYPTOFUZZ_DIR"

make generate_kem_corpus generate_pqsign_corpus

./generate_kem_corpus "$CRYPTOFUZZ_DIR/corpus/kem"
./generate_pqsign_corpus "$CRYPTOFUZZ_DIR/corpus/pqsign"
```

## 12. Generate Valid Corpus Seeds with liboqs

Some corpus seeds are generated using liboqs so that the fuzzer starts with valid cryptographic material, such as key pairs, ciphertexts, shared secrets, and signatures.

Export the liboqs paths before creating these valid seeds:

```bash
export LIBOQS_A_PATH="$LIBOQS_DIR/build/lib/liboqs.a"
export LIBOQS_INCLUDE_PATH="$LIBOQS_DIR/build/include"
```

Then build and run the valid-seed generators:

```bash
cd "$CRYPTOFUZZ_DIR"

make generate_kem_valid_seeds generate_pqsign_valid_seeds

./generate_kem_valid_seeds "$CRYPTOFUZZ_DIR/corpus/kem"
./generate_pqsign_valid_seeds "$CRYPTOFUZZ_DIR/corpus/pqsign"
```

## 13. Run an ML-KEM Fuzzing Campaign

The following command starts an ML-KEM fuzzing campaign using all three ML-KEM parameter sets and the KEM operations added in this extension.

```bash
cd "$CRYPTOFUZZ_DIR"

./cryptofuzz -workers=5 -jobs=10 \
  -max_total_time=5400 \
  -seed=42 \
  -artifact_prefix="$CRYPTOFUZZ_DIR/crashes/kem/" \
  -print_final_stats=1 \
  -rss_limit_mb=4096 \
  --kemtypes=ML-KEM-512,ML-KEM-768,ML-KEM-1024 \
  --operations=KEM_GenerateKeyPair,KEM_Encapsulate,KEM_Decapsulate \
  --min-modules=2 \
  "$CRYPTOFUZZ_DIR/corpus/kem"
```

## 14. Run an ML-DSA Fuzzing Campaign

The following command starts an ML-DSA fuzzing campaign using all three ML-DSA parameter sets and the PQSign operations added in this extension.

cd "$CRYPTOFUZZ_DIR"

```bash
./cryptofuzz -workers=5 -jobs=10 \
  -max_total_time=5400 \
  -seed=42 \
  -artifact_prefix="$CRYPTOFUZZ_DIR/crashes/pqsign/" \
  -print_final_stats=1 \
  -rss_limit_mb=4096 \
  --pqsigntypes=ML-DSA-44,ML-DSA-65,ML-DSA-87 \
  --operations=PQSign_GenerateKeyPair,PQSign_Sign,PQSign_Verify \
  --min-modules=2 \
  "$CRYPTOFUZZ_DIR/corpus/pqsign"
```