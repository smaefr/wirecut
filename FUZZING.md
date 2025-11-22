# Fuzzing wirecut

The harness in `fuzz/fuzz_parser.cpp` feeds every input to `wirecut::parse`.
The default parser is expected to stay clean under AddressSanitizer and
UndefinedBehaviorSanitizer: no crashes, no OOB, no use-after-free, no
signed overflow, no misaligned UB from this code.

## Build the fuzzer

Requires Clang with libFuzzer (compiler-rt).

```bash
CC=clang CXX=clang++ cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DWIRECUT_FUZZER=ON
cmake --build build-fuzz --target wirecut-fuzz
mkdir -p fuzz-work fuzz-out
cp -a corpus/. fuzz-work/
./build-fuzz/wirecut-fuzz fuzz-work -artifact_prefix=fuzz-out/ \
  -max_total_time=60 -timeout=2
```

libFuzzer writes new coverage units into the first corpus directory. Copy
`corpus/` into `fuzz-work/` (gitignored) so the checked-in seeds stay small.

Short smoke run (skips if `clang++` is missing):

```bash
make fuzz-short
```

CMake turns on `-fsanitize=address,undefined` for the library and
`-fsanitize=fuzzer,address,undefined` for the harness when `WIRECUT_FUZZER=ON`.

## Sanitizer flags

Unit tests (`make test`):

```
-fsanitize=address,undefined -fno-omit-frame-pointer
ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
```

Do not enable `WIRECUT_HISTORICAL_UNSAFE` for fuzzing or CI. That define
exists only to document a fixed bounds bug and will reintroduce an OOB copy.

## Corpus

`corpus/` holds small seeds: valid empty list, one TLV, several TLVs,
truncated header, truncated value, claimed length past remaining bytes, bad
magic, and bad version. libFuzzer mutates these toward the 4096-byte cap.

Crash artifacts (`crash-*`, `oom-*`, `timeout-*`) are gitignored. Re-run a
saved crash with:

```bash
./build-fuzz/wirecut-fuzz crash-<hash>
```

## Past ASan finding (fixed)

**When:** early draft of `wirecut::parse`, caught by libFuzzer + ASan.

**Symptom:** heap-buffer-overflow READ while copying a TLV value.

**Trigger:** a well-formed header (`WCT1`, version `1`, `n_tlvs = 1`) followed
by tag `0x01` and a big-endian length of `0x0100` (256), with only four value
bytes actually present. Total buffer length was 13 bytes (`6` header + `1`
tag + `2` length + `4` payload).

**Root cause:** the parser read `length` and then did the equivalent of
copying `length` bytes from `data + offset + 3` without checking
`length <= remain - 3`. ASan reported a READ of size 256 past the end of the
input allocation in `wirecut::parse`.

**Fix:** after confirming at least 3 bytes remain for tag and length, reject
with `ParseStatus::LengthOverflow` when `length > remain - 3`. Only then
copy `length` bytes. There is no `memcpy` of an untrusted length without that
check. See `src/parser.cpp`.

**Regression test:** `test_length_overflow` in `tests/test_parser.cpp` (and
the `corpus` seed with an oversized claimed length).

Current default code must pass ASan/UBSan on the unit tests and on the
fuzzer harness. The historical path is compile-time only
(`-DWIRECUT_HISTORICAL_UNSAFE`) and is not used in `make test`, CI, or
`make fuzz-short`.
