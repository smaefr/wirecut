# SPDX-License-Identifier: MIT
# Thin wrapper around CMake. `make test` is expected to finish in under 60s.

BUILD_DIR ?= build
FUZZ_DIR ?= build-fuzz
COV_DIR ?= build-cov
CMAKE ?= cmake
JOBS ?= $(shell nproc 2>/dev/null || echo 2)

.PHONY: all test fuzz-short coverage clean

all: $(BUILD_DIR)/wirecut-tests

$(BUILD_DIR)/wirecut-tests:
	mkdir -p $(BUILD_DIR)
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build $(BUILD_DIR) -j$(JOBS)

test:
	mkdir -p $(BUILD_DIR)
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug -DWIRECUT_SANITIZE=ON
	$(CMAKE) --build $(BUILD_DIR) -j$(JOBS)
	ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(BUILD_DIR)/wirecut-tests

fuzz-short:
	@if ! command -v clang++ >/dev/null 2>&1; then \
		echo "clang++ not found; skipping fuzz-short"; \
		exit 0; \
	fi
	mkdir -p $(FUZZ_DIR)
	CC=clang CXX=clang++ $(CMAKE) -S . -B $(FUZZ_DIR) \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo -DWIRECUT_FUZZER=ON
	$(CMAKE) --build $(FUZZ_DIR) --target wirecut-fuzz -j$(JOBS)
	mkdir -p fuzz-work fuzz-out
	cp -a corpus/. fuzz-work/
	$(FUZZ_DIR)/wirecut-fuzz fuzz-work -artifact_prefix=fuzz-out/ \
		-max_total_time=5 -timeout=2 -print_final_stats=1

coverage:
	mkdir -p $(COV_DIR)
	$(CMAKE) -S . -B $(COV_DIR) -DCMAKE_BUILD_TYPE=Debug -DWIRECUT_COVERAGE=ON
	$(CMAKE) --build $(COV_DIR) --target wirecut-tests -j$(JOBS)
	LLVM_PROFILE_FILE="$(CURDIR)/$(COV_DIR)/default.profraw" $(COV_DIR)/wirecut-tests
	python3 scripts/check_parser_coverage.py $(COV_DIR)

clean:
	rm -rf $(BUILD_DIR) $(FUZZ_DIR) $(COV_DIR)
