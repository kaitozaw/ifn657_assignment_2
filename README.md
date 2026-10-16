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
cd sentinel_network/
```

#### 1. Compilation

```bash
afl-clang-fast -m32 -std=c99 -w -g -o sentinel_network_nosan sentinel_network.c
```

```bash
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast -m32 -std=c99 -w -g -o sentinel_network_asan_ubsan sentinel_network.c
```

```bash
AFL_USE_MSAN=1 afl-clang-fast -std=c99 -w -g -o sentinel_network_msan sentinel_network.c
```

#### 2. Fuzzing Status

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S asan_ubsan -- ./sentinel_network_asan_ubsan @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S msan       -- ./sentinel_network_msan       @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan1     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan2     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan3     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &

afl-fuzz -i seeds -o findings -x dict -M master_nosan -- ./sentinel_network_nosan @@
```

#### 3. Crash Triage

```bash
mkdir -p crash_logs
for f in findings/*/crashes/id:*; do
  name=$(echo "$f" | tr '/:,' '___')
  timeout 10 ./sentinel_{target}_asan_ubsan "$f" > "crash_logs/$name.log" 2>&1
  echo "$f" >> "crash_logs/$name.log"   # record the original crash file on the last line
done
```

```bash
./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow02.bin
./sentinel_network_asan_ubsan crash_analysis/negative-size-param01.bin
./sentinel_network_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
./sentinel_network_asan_ubsan crash_analysis/heap-use-after-free01.bin
./sentinel_network_asan_ubsan crash_analysis/heap-use-after-free02.bin
```

```bash
gdb --args ./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
gdb --args ./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow02.bin
gdb --args ./sentinel_network_asan_ubsan crash_analysis/negative-size-param01.bin
gdb --args ./sentinel_network_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
gdb --args ./sentinel_network_asan_ubsan crash_analysis/heap-use-after-free01.bin
gdb --args ./sentinel_network_asan_ubsan crash_analysis/heap-use-after-free02.bin
```

#### 4. Remediation Verification

```bash
./sentinel_network_remediated crash_analysis/stack-buffer-overflow01.bin
./sentinel_network_remediated crash_analysis/stack-buffer-overflow02.bin
./sentinel_network_remediated crash_analysis/negative-size-param01.bin
./sentinel_network_remediated crash_analysis/heap-buffer-overflow01.bin
./sentinel_network_remediated crash_analysis/heap-use-after-free01.bin
./sentinel_network_remediated crash_analysis/heap-use-after-free02.bin
```

#### 5. Proof-of-Concept

```bash
python3 exploits/exploit.py
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
./sentinel_network_original exploits/exploit.bin
echo $?
# -> 24, not 0 (normal main return) nor a crash code (134/139): the saved return address was hijacked to exit(), so control never returned to main.
```

---