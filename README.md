# IFN657 Assignment 2

Fuzzing, crash triage and remediation of three targets: `sentinel_network`, `sentinel_payload`, `sentinel_telemetry`.

## Directory Structure

```
.
├── crashes/                 # Representative crash inputs per target
├── exploits/                # Exploit inputs per target
├── images/                  # Screenshots (AFL++ status, stats) per target
├── remediated_src/          # Remediated source code per target
├── seeds/                   # Seed inputs per target
├── sentinel_network/        # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── sentinel_payload/        # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── sentinel_telemetry/      # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── targets/                 # Original target sources and initial seeds
├── as2_report_template.md   # Report template
├── as2.pdf                  # Assignment specification
├── Group_01.md              # Group report
└── README.md                # This document
```

## Execution Instructions

### `sentinel_telemetry.c`

```bash
```

---

### `sentinel_payload.c`

```bash
cd sentinel_payload/
```

#### 1. Compilation

```bash
afl-clang-fast -m32 -std=c99 -w -g -o sentinel_payload_nosan sentinel_payload.c
```

```bash
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1
afl-clang-fast -m32 -std=c99 -w -g -o sentinel_payload_asan_ubsan sentinel_payload.c
```

```bash
export AFL_USE_MSAN=1
afl-clang-fast -m32 -std=c99 -w -g -o sentinel_payload_msan sentinel_payload.c
```

#### 2. Fuzzing Status

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
afl-fuzz -i seeds -o out -x sentinel_payload.dict -m none -M nosan ./sentinel_payload_nosan @@
afl-fuzz -i seeds -o out -x sentinel_payload.dict -m none -S asan_ubsan ./sentinel_payload_asan_ubsan @@
afl-fuzz -i seeds -o out -x sentinel_payload.dict -m none -S msan ./sentinel_payload_msan @@
```

#### 3. Crash Triage

```bash
mkdir -p crash_logs
for f in out/*/crashes/id:*; do
  name=$(echo "$f" | tr '/:,' '___')
  timeout 10 ./sentinel_payload_asan_ubsan "$f" > "crash_logs/$name.log" 2>&1
  echo "$f" >> "crash_logs/$name.log"
done
```

```bash
./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_asan_ubsan crash_analysis/heap-use-after-free01.bin
./sentinel_payload_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
./sentinel_payload_msan crash_analysis/format-string-vulnerability01.bin
```

```bash
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/heap-use-after-free01.bin
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
gdb --args ./sentinel_payload_msan crash_analysis/format-string-vulnerability01.bin
```

#### 4. Remediation Verification

```bash
./sentinel_payload_remediated crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_remediated crash_analysis/heap-use-after-free01.bin
./sentinel_payload_remediated crash_analysis/stack-buffer-overflow01.bin
./sentinel_payload_remediated crash_analysis/format-string-vulnerability01.bin
```

---

### `sentinel_network.c`

```bash
```