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
for log in crash_logs/*.log; do
  key=$(awk '
    /ERROR: AddressSanitizer:/ && !type {
      match($0, /AddressSanitizer: [a-z-]+/); type=substr($0, RSTART+18, RLENGTH-18); next }
    type && /^ *#[0-9]+ / {
      sub(/^ *#[0-9]+ 0x[0-9a-f]+ in /, "")
      gsub(/\/[^ ]*\//, "")
      if ($0 ~ /:[0-9]+:[0-9]+$/) sub(/:[0-9]+$/, "")
      if ($0 ~ /^(__asan|__interceptor|__sanitizer)/) next
      key = key " > " $0
      if (++n == 3) exit
    }
    type && n && /^$/ { exit }
    END { print (type ? type : "no-repro") " |" key }' "$log")
  printf "%s\t%s\n" "$key" "$(tail -1 "$log")"
done > crash_buckets.tsv
```

```bash
mkdir -p crash_analysis
declare -A num
awk -F'\t' '
  { cnt[$1]++; if (!($1 in rep)) rep[$1] = $2 }
  END { for (k in cnt) printf "%d\t%s\t%s\n", cnt[k], k, rep[k] }
' crash_buckets.tsv \
| sort -t$'\t' -k1,1nr \
| while IFS=$'\t' read -r cnt key rep; do
    type=${key%% |*}
    num[$type]=$(( ${num[$type]:-0} + 1 ))
    name=$(printf "%s%02d" "$type" "${num[$type]}")
    printf "[%d crashes] %s\nbucket: %s\nrepresentative crash: %s\n\n" "$cnt" "$name" "$key" "$rep"
    [ "$type" = "no-repro" ] && continue
    afl-tmin -i "$rep" -o "crash_analysis/$name.bin" -- ./sentinel_payload_asan_ubsan @@ < /dev/null > /dev/null 2>&1
  done
```

```bash
./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_asan_ubsan crash_analysis/heap-use-after-free01.bin
./sentinel_payload_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
./sentinel_payload_msan crash_analysis/stack-buffer-underflow01.bin
```

```bash
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/heap-use-after-free01.bin
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/stack-buffer-overflow01.bin
gdb --args ./sentinel_payload_msan crash_analysis/stack-buffer-underflow01.bin
```

#### 4. Remediation Verification

```bash
./sentinel_payload_remediated crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_remediated crash_analysis/heap-use-after-free01.bin
./sentinel_payload_remediated crash_analysis/stack-buffer-overflow01.bin
./sentinel_payload_remediated crash_analysis/stack-buffer-underflow01.bin
```

---

### `sentinel_network.c`

```bash
```