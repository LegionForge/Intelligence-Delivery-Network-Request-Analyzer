# IDN Request Analyzer — Build System
# Targets: native .so, WASM, ESP32, Arduino

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c99 -Isrc
SRC     = src/signals_core.c
HDR     = src/signals_core.h

# ── Native shared library (Linux/macOS) ──────────────────────────────────────
.PHONY: native
native:
	$(CC) $(CFLAGS) -shared -fPIC -o src/signals_core.so $(SRC)
	@echo "✅ Built: src/signals_core.so"

# ── macOS dylib ───────────────────────────────────────────────────────────────
.PHONY: macos
macos:
	$(CC) $(CFLAGS) -shared -dynamiclib -o src/signals_core.dylib $(SRC)
	@echo "✅ Built: src/signals_core.dylib"

# ── Windows DLL (cross-compile) ───────────────────────────────────────────────
.PHONY: windows
windows:
	x86_64-w64-mingw32-gcc $(CFLAGS) -shared -o src/signals_core.dll $(SRC)
	@echo "✅ Built: src/signals_core.dll"

# ── WASM (requires Emscripten) ────────────────────────────────────────────────
.PHONY: wasm
wasm:
	emcc $(CFLAGS) -s EXPORTED_FUNCTIONS='["_idn_analyze","_idn_tier_name","_idn_domain_name"]' \
	     -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap"]' \
	     -s ALLOW_MEMORY_GROWTH=1 \
	     -o build/signals_core.wasm $(SRC)
	@echo "✅ Built: build/signals_core.wasm"

# ── ESP32 (requires ESP-IDF or Arduino CLI) ───────────────────────────────────
.PHONY: esp32
esp32:
	xtensa-esp32-elf-gcc $(CFLAGS) -c -o build/signals_core_esp32.o $(SRC)
	@echo "✅ Built: build/signals_core_esp32.o (link with your ESP-IDF project)"

# ── ARM (Raspberry Pi cross-compile) ─────────────────────────────────────────
.PHONY: arm
arm:
	arm-linux-gnueabihf-gcc $(CFLAGS) -shared -fPIC -o build/signals_core_arm.so $(SRC)
	@echo "✅ Built: build/signals_core_arm.so"

# ── Test (requires pytest) ────────────────────────────────────────────────────
.PHONY: test
test:
	pytest tests/test_signals.py -v

# ── Clean ─────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	rm -f src/*.so src/*.dylib src/*.dll build/*.wasm build/*.o

# ── Build directory ───────────────────────────────────────────────────────────
build:
	mkdir -p build

.DEFAULT_GOAL := native
