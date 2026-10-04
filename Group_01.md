# IFN657 Assignment 2: Vulnerability Discovery

**Group ID:** `Group_01`
**Submission Date:** `[16 October 2026]`  

### Team Members & Workload Distribution
| Student Name | Student ID | Email Address | Assigned Subtasks / Roles | Contribution (%) |
| :--- | :--- | :--- | :--- | :--- |
| `Clair Lin`   | `[n0000001]`  | `c229.lin@connect.qut.edu.au`    | `Fuzz testing of sentinel_telemetry.c` | 33.3% |
| `Rachel Lim`  | `[n0000002]`  | `r20.lim@connect.qut.edu.au`     | `Fuzz testing of sentinel_payload.c`   | 33.3% |
| `Kaito Ozawa` | `[n12224774]` | `kaito.ozawa@connect.qut.edu.au` | `Fuzz testing of sentinel_network.c`   | 33.3% |

**Submission Files (Canvas):**
- `Group_01.pdf` (compiled from this completed Markdown report template)
- `Group_01.zip` (archive containing `seeds/`, `crashes/`, `exploits/`, `remediated_src/`, `README.md`, and `Group_XX.cast`)

---

## Table of Contents
1. [Task 0: Executive Summary](#1-task-0-executive-summary)
2. [Task 1: Setup](#2-task-1-setup)
3. [Task 2: Fuzzing Execution](#3-task-2-fuzzing-execution)
4. [Task 3: Vulnerability Analysis](#4-task-3-vulnerability-analysis)
5. [Task 4: Code Remediation](#5-task-4-code-remediation)
6. [Task 5: Proof-of-Concept Exploitation](#6-task-5-proof-of-concept-exploitation)

---

## 1. Task 0: Executive Summary

| Task | Status | `asciinema` Timestamp (mm:ss) | Notes |
| :--- | :--- | :--- | :--- |
| **Task 0: Claims, Demo & Teamwork** | [Completed / Incomplete] | [00:00] | Any additional notes. |
| **Task 1: Setup** | [Completed / Incomplete]  | [00:30] | Briefly describe how this task is completed. |
| **Task 2: Fuzzing Execution** | [Completed / Incomplete]  | [01:30] | Briefly describe how this task is completed. |
| **Task 3: Vulnerability Analysis** | [Completed / Incomplete]  | [03:00] | Briefly describe how this task is completed. |
| **Task 4: Code Remediation** | [Completed / Incomplete]  | [05:30] | Briefly describe how this task is completed. |
| **Task 5: Proof-of-Concept Exploitation** | [Completed / Incomplete]  | [07:00] | Briefly describe how this task is completed. |
| **Total Number of Distinct Vulnerabilities Found** | [The total number] | N/A | Any additional notes. |

---

## 2. Task 1: Setup

### 2.1 Compilation & Target Environment Setup

sentinel_telemetry
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern

# Compilation commands with AFL++ instrumentation

# Compilation commands with AddressSanitizer and UndefinedBehaviorSanitizer

```

sentinel_payload
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern

# Compilation commands with AFL++ instrumentation

# Compilation commands with AddressSanitizer and UndefinedBehaviorSanitizer

```

sentinel_network
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern

# Compilation commands with AFL++ instrumentation
afl-clang-fast -m32 -std=c99 -w -g -o sentinel_network_nosan sentinel_network.c

# Compilation commands with AddressSanitizer and UndefinedBehaviorSanitizer
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast -m32 -std=c99 -w -g -o sentinel_network_asan_ubsan sentinel_network.c

# Compilation commands with MemorySanitizer
AFL_USE_MSAN=1 afl-clang-fast -std=c99 -w -g -o sentinel_network_msan sentinel_network.c
```

### 2.2 Seed Corpus

#### Target 1: `sentinel_telemetry` Seed Set
| Seed Filename | Input Content / Syntax Summary | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- |
| `seed_telemetry.conf` | Starter configuration with nominal directives | Base parser validation and comment handling |
| `seed_tel_2.conf` | `[Describe content]` | `[Describe branch/rationale]` |
| `seed_tel_3.conf` | `[Describe content]` | `[Describe branch/rationale]` |
| `seed_tel_X.conf` | `[Describe content]` | `[Describe branch/rationale]` |

#### Target 2: `sentinel_payload` Seed Set
| Seed Filename | Dimensions & Label | Payload Size | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_payload.bin` | `PAYLOAD_FRAME 8 8 1 RADAR_SCAN_01` | 64 bytes | Standard 2D observation matrix |
| `seed_pay_2.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |
| `seed_pay_3.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |
| `seed_pay_X.bin` | `[Describe parameters]` | `[Size]` | `[Describe branch/rationale]` |

#### Target 3: `sentinel_network` Seed Set
| Seed Filename | Magic Header & Type | Payload Length | Target Branch / Parsing State Exercised |
| :--- | :--- | :--- | :--- |
| `seed_net_1.bin` | `0x12345678`, Type 1          | 16 bytes | Type 1, small payload                               |
| `seed_net_2.bin` | `0x12345678`, Type 1          | 48 bytes | Type 1, larger payload within header summary buffer |
| `seed_net_3.bin` | `0x12345678`, Type 2          | 4 bytes  | Type 2, payload below 8-byte overflow threshold.    |
| `seed_net_4.bin` | `0x12345678`, Type 1 + Type 2 | 20 bytes | Multi-message input (seeds 1 + 3)                   |

### 2.3 Seed Generation Methodology & Helper Scripts

sentinel_telemetry: ~~.py
```python
## if needed (might not be necessary)
```

sentinel_payload: ~~.py
```python
## if needed (might not be necessary)
```

sentinel_network: seeds_net.py
```python
import struct

def pkt(t, n):
    return struct.pack("<IHH", 0x12345678, t, n) + b"A" * (n - 1) + b"\x00"

seeds = [
    pkt(1, 16),
    pkt(1, 48),
    pkt(2, 4),
    pkt(1, 16) + pkt(2, 4),
]

for i, data in enumerate(seeds, 1):
    open(f"seeds/seed_net_{i}.bin", "wb").write(data)
```

---

## 3. Task 2: Fuzzing Execution

### 3.1 Fuzzing Execution & Advanced Techniques

#### sentinel_telemetry

```bash
# Example AFL++ execution commands used by your team

```

**Technical Justification:**
`[Explain why these options and techniques were chosen and how they improved coverage/efficiency]`

#### sentinel_payload

```bash
# Example AFL++ execution commands used by your team

```

**Technical Justification:**
`[Explain why these options and techniques were chosen and how they improved coverage/efficiency]`

#### sentinel_network

persistent in-process fuzzing: sentinel_network.c
```c
int old_main(int argc, char **argv) {
}

int main(int argc, char **argv) {
    int res = 0;
    while (__AFL_LOOP(10000)) {
        memset(active_telecommands, 0, sizeof(active_telecommands));
        active_telecommand_count = 0;
        res = old_main(argc, argv);
    }
    return res;
}
```

dictionaries: dict
```bash
magic="\x78\x56\x34\x12"
type_1="\x01\x00"
type_2="\x02\x00"
type_3="\x03\x00"
len_0="\x00\x00"
len_4="\x04\x00"
len_16="\x10\x00"
len_1016="\xf8\x03"
len_1024="\x00\x04"
len_max="\xff\xff"
```

multi-core parallel fuzzing
```bash
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S asan_ubsan -- ./sentinel_network_asan_ubsan @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S msan       -- ./sentinel_network_msan       @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan1     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan2     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &
AFL_NO_UI=1 nohup afl-fuzz -i seeds -o findings -x dict -S nosan3     -- ./sentinel_network_nosan      @@ > /dev/null 2>&1 &

afl-fuzz -i seeds -o findings -x dict -M master_nosan -- ./sentinel_network_nosan @@

# open another terminal and check the aggregated status
afl-whatsup -s findings

# kill all the processes
pkill afl-fuzz
```

**Technical Justification:**
Persistent mode (`__AFL_LOOP`) removes the cost of starting a new process for each input, which greatly increases exec/s. The dictionary supplies the magic header, message types and boundary lengths so mutations get past the header checks, and the parallel instances combine fast uninstrumented runs for coverage with ASan/UBSan and MSan builds that catch memory errors which would otherwise go undetected.

### 3.2 Campaign Performance & Coverage Metrics

| Target Program | Campaign Duration | Total Executions | Execution Speed (exec/s) | Total Paths Discovered | Unique Crashes Reported |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `sentinel_telemetry` | `[e.g. 6.5 hours]` | `[e.g. 12.4M]` | `[e.g. 1,250/sec]` | `[e.g. 48 paths]` | `[e.g. 14 crashes]` | 
| `sentinel_payload` | `[Hours]` | `[Executions]` | `[Exec/sec]` | `[Paths]` | `[Crashes]` | 
| `sentinel_network` | 2.4 hours | 22M | 2,630/sec | 72 paths | 103 crashes |

### 3.3 AFL++ Status Console Screenshots

sentinel_telemetry
```
[Insert Screenshot: sentinel_telemetry AFL++ Status Screen]
```

sentinel_payload
```
[Insert Screenshot: sentinel_payload AFL++ Status Screen]
```

sentinel_network
![sentinel_network AFL++ Status Screen](images/sentinel_network_afl_status_screen.png)
![sentinel_network AFL++ Summary Stats](images/sentinel_network_afl_summary_stats.png)

---

## 4. Task 3: Vulnerability Analysis

### 4.1 Crash Triage Methodology

The same methodology was applied to all three targets. In the commands below, `{target}` is one of `telemetry`, `payload`, or `network`.

1. replay all crashes with the ASan build and save full logs

```bash
mkdir -p crash_logs
for f in findings/*/crashes/id:*; do
  name=$(echo "$f" | tr '/:,' '___')
  timeout 10 ./sentinel_{target}_asan_ubsan "$f" > "crash_logs/$name.log" 2>&1
  echo "$f" >> "crash_logs/$name.log"   # record the original crash file on the last line
done
```

2. build a bucket key (error type + top 3 frames) for each crash

```bash
for log in crash_logs/*.log; do
  key=$(awk '
    /ERROR: AddressSanitizer:/ && !type {
      match($0, /AddressSanitizer: [a-z-]+/); type=substr($0, RSTART+18, RLENGTH-18); next }
    type && /^ *#[0-9]+ / {
      sub(/^ *#[0-9]+ 0x[0-9a-f]+ in /, "")        # remove frame number and address
      gsub(/\/[^ ]*\//, "")                        # remove directory paths
      if ($0 ~ /:[0-9]+:[0-9]+$/) sub(/:[0-9]+$/, "")  # remove column number
      if ($0 ~ /^(__asan|__interceptor|__sanitizer)/) next  # skip ASan internal frames
      key = key " > " $0
      if (++n == 3) exit                           # stop after top 3 frames
    }
    type && n && /^$/ { exit }                     # stop at the end of the first stack
    END { print (type ? type : "no-repro") " |" key }' "$log")
  printf "%s\t%s\n" "$key" "$(tail -1 "$log")"
done > crash_buckets.tsv
```

3. count crashes per bucket, pick one representative crash and minimise it

```bash
mkdir -p crash_analysis
declare -A num                                                   # per-error-type counter
awk -F'\t' '
  { cnt[$1]++; if (!($1 in rep)) rep[$1] = $2 }                  # count crashes and keep the first file per bucket
  END { for (k in cnt) printf "%d\t%s\t%s\n", cnt[k], k, rep[k] }
' crash_buckets.tsv \
| sort -t$'\t' -k1,1nr \
| while IFS=$'\t' read -r cnt key rep; do
    type=${key%% |*}                                             # error type (text before " |")
    num[$type]=$(( ${num[$type]:-0} + 1 ))
    name=$(printf "%s%02d" "$type" "${num[$type]}")              # e.g. heap-buffer-overflow01
    printf "[%d crashes] %s\nbucket: %s\nrepresentative crash: %s\n\n" "$cnt" "$name" "$key" "$rep"
    [ "$type" = "no-repro" ] && continue                         # skip crashes that did not reproduce
    afl-tmin -i "$rep" -o "crash_analysis/$name.bin" -- ./sentinel_{target}_asan_ubsan @@ < /dev/null > /dev/null 2>&1  # keep only the bytes needed to trigger the same crash
  done
```

4. decode the input as a packet sequence (`network` only)

```bash
xxd crash_analysis/{name}.bin
```

5. match the sanitizer report against the source code (filter depends on the vulnerability type)

```bash
# stack buffer overflow
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "ERROR|WRITE|READ|located in stack|frame has|<== Memory access|#[0-3] "

# heap buffer overflow
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "ERROR|WRITE|READ|located|allocated by|#[0-3] "

# format string vulnerability
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "ERROR|WRITE|READ|printf|#[0-5] "
grep -aoE '%[0-9.$-]*[a-zA-Z]+' crash_analysis/{name}.bin | sort | uniq -c

# integer overflow/underflow
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "runtime error|negative-size-param|ERROR|located|allocated by|#[0-3] "

# use-after-free
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "ERROR|WRITE|READ|located|freed by|allocated by|#[0-3] "

# double-free
./sentinel_{target}_asan_ubsan crash_analysis/{name}.bin 2>&1 | grep -E "ERROR|double-free|freed by|allocated by|#[0-3] "

# uninitialised memory access
./sentinel_network_msan crash_analysis/{name}.bin 2>&1 | grep -E "MemorySanitizer|Uninitialized value|#[0-3] "
```

### 4.2 Discovered Vulnerabilities

---

#### 4.2.1 Vulnerability 1
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Format String Vulnerability in Telemetry Logger]` |
| **CWE Classification** | `[e.g. CWE-134: Use of Externally-Controlled Format String]` |
| **Target Component** | `[e.g. sentinel_telemetry.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000000_telemetry_crash.conf]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact (e.g. memory leak, DoS, arbitrary write)]`

---

#### 4.2.2 Vulnerability 2
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Integer Overflow in Stream Buffer Calculation]` |
| **CWE Classification** | `[e.g. CWE-190: Integer Overflow or Wraparound]` |
| **Target Component** | `[e.g. sentinel_telemetry.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000001_stream_overflow.conf]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.3 Vulnerability X (numbered sequentially for each distinct vulnerability)
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `[e.g. Stack Buffer Overflow in Frame Label Processing]` |
| **CWE Classification** | `[e.g. CWE-121: Stack-based Buffer Overflow]` |
| **Target Component** | `[e.g. sentinel_payload.c]` |
| **Vulnerable Location** | `[Function name, line number, and code snippet]` |
| **Reproducing Input File** | `[e.g. crashes/id_000002_payload_label_overflow.bin]` |

**Triggering Input & Reproduction Command:**
```bash
# Provide command to reproduce the crash

```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
[Paste annotated Sanitiser error report or GDB backtrace here]
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.11 Vulnerability 11
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `Stack Buffer Overflow in Telecommand Header Logging` |
| **CWE Classification** | `CWE-121: Stack-based Buffer Overflow` (+ `CWE-125: Out-of-bounds Read`) |
| **Target Component** | `sentinel_network.c` |
| **Vulnerable Location** | `log_telecommand_header()` L43: `sprintf(header_summary, "... Data: %s", ..., (char *)pkt->data)` |
| **Reproducing Input File** | `crash_analysis/stack-buffer-overflow1.bin` (write), `crash_analysis/stack-buffer-overflow2.bin` (read) |

**Triggering Input & Reproduction Command:**
```bash
./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow1.bin   # overflow write into header_summary
./sentinel_network_asan_ubsan crash_analysis/stack-buffer-overflow2.bin   # over-read past input_stream
```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
# stack-buffer-overflow1.bin
ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 131 ...                                          <- formatted string exceeds 128 bytes
  [WRITE] sprintf <- log_telecommand_header sentinel_network.c:43
  [16, 144) 'header_summary' (line 36) <== Memory access at offset 144 overflows this variable

# stack-buffer-overflow2.bin
ERROR: AddressSanitizer: stack-buffer-overflow
READ of size 1017 ...                                          <- %s reads pkt->data with no NUL terminator
  [READ]  sprintf <- log_telecommand_header sentinel_network.c:43
  [16, 1040) 'input_stream' (line 156) <== Memory access at offset 1040 overflows this variable
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.12 Vulnerability 12
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `Integer Underflow in Payload Size Calculation Leading to Heap Buffer Overflow` |
| **CWE Classification** | `CWE-191: Integer Underflow` → `CWE-122: Heap-based Buffer Overflow` |
| **Target Component** | `sentinel_network.c` |
| **Vulnerable Location** | `calculate_telecommand_payload_size()` L89 (root cause) → `append_telecommand_payload()` L68 (crash site): `(size_t)(total_packet_length - header_overhead)` |
| **Reproducing Input File** | `crash_analysis/negative-size-param.bin` |

**Triggering Input & Reproduction Command:**
```bash
xxd crash_analysis/negative-size-param.bin
# 00000000: 7856 3412 0100 0400 4141 4100            xV4.....AAA.   <- packet 1: type=1, length=4

./sentinel_network_asan_ubsan crash_analysis/negative-size-param.bin
```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
ERROR: AddressSanitizer: negative-size-param: (size=-4)        <- 4 - 8 underflowed; ASan aborts before memcpy copies
  [COPY]  append_telecommand_payload sentinel_network.c:68   <- dispatch:128      (packet 1, type=1, length=4)
Address ... is located in stack ... in frame old_main          <- source pkt->data points into input_stream (stack)
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.13 Vulnerability 13
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `Heap Buffer Overflow in Thruster Calibration Payload Copy` |
| **CWE Classification** | `CWE-122: Heap-based Buffer Overflow` |
| **Target Component** | `sentinel_network.c` |
| **Vulnerable Location** | `dispatch_telecommand()` L134-136 (root cause) → `append_telecommand_payload()` L68 (crash site): `memcpy(msg->buffer, payload_data, copy_length);` |
| **Reproducing Input File** | `crash_analysis/heap-buffer-overflow.bin` |

**Triggering Input & Reproduction Command:**
```bash
xxd crash_analysis/heap-buffer-overflow.bin
# 00000000: 7856 3412 0100 1000 4141 4141 4147 4141  xV4.....AAAAAGAA   <- packet 1: type=1, length=16
# 00000010: 4141 40f4 0100 2000 7856 3412 0200 0c00  AA@... .xV4.....   <- packet 2: type=2, length=12
# 00000020: 0000 1000 0041 4141 4141 3c00            .....AAAAA<.

./sentinel_network_asan_ubsan crash_analysis/heap-buffer-overflow.bin
```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 12 ... 0 bytes after 4-byte region                <- copies length (12) into length - 8 (4) bytes
  [WRITE] append_telecommand_payload sentinel_network.c:68   <- dispatch:136      (packet 2, type=2)
  [ALLOC] create_telecommand_record  sentinel_network.c:53   <- dispatch:134      (packet 2, type=2)
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.14 Vulnerability 14
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `Heap Use After Free in Active Telecommands` |
| **CWE Classification** | `CWE-416: Use After Free` |
| **Target Component** | `sentinel_network.c]` |
| **Vulnerable Location** | `emergency_command_cleanup()` L81-84 (root cause) → `release_telecommand_record()` L73 (crash site): `if (msg->buffer) {` |
| **Reproducing Input File** | `crash_analysis/heap-use-after-free.bin` |

**Triggering Input & Reproduction Command:**
```bash
xxd crash_analysis/heap-use-after-free.bin
# 00000000: 7856 3412 0100 1000 4141 4141 4141 4141  xV4.....AAAAAAAA   <- packet 1: type=1, length=16
# 00000010: 4141 4141 4141 4100 7856 3412 0300 0400  AAAAAAA.xV4.....   <- packet 2: type=3, length=4
# 00000020: 4141 4100                                AAA.

./sentinel_network_asan_ubsan crash_analysis/heap-use-after-free.bin
```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
ERROR: AddressSanitizer: heap-use-after-free
READ of size 4 ... 0 bytes inside of 12-byte region            <- msg->buffer of freed msg
  [USE]   release_telecommand_record sentinel_network.c:73   <- old_main:189      (2nd cleanup)
  [FREE]  release_telecommand_record sentinel_network.c:77   <- dispatch:142      (packet 2, type=3)
  [ALLOC] create_telecommand_record  sentinel_network.c:49   <- dispatch:126      (packet 1, type=1)
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

#### 4.2.15 Vulnerability 15
| Field | Details |
| :--- | :--- |
| **Vulnerability Name** | `Misaligned Packet Header Access on Unaligned Stream Offset` |
| **CWE Classification** | `CWE-1319: Improper Protection against Unaligned Access` (reported by UBSan) |
| **Target Component** | `sentinel_network.c` |
| **Vulnerable Location** | `validate_packet_integrity()` L94: `if (pkt->magic != PROTOCOL_MAGIC_HEADER)` (pkt cast from an unaligned `input_stream + offset`) |
| **Reproducing Input File** | `crash_analysis/misaligned-access.bin` |

**Triggering Input & Reproduction Command:**
```bash
xxd crash_analysis/misaligned-access.bin
# 00000000: 7856 3412 0100 0f00 3412 0200 4141 4a41  xV4.....4...AAJA   <- packet 1: type=1, length=15 (odd)
# 00000010: 4141 4141 4141 4141 4141 4100 ...         next packet starts at offset 8+15=23 (unaligned)

./sentinel_network_asan_ubsan crash_analysis/misaligned-access.bin
```

**Root Cause Analysis:**
`[Explain the technical root cause, memory state, and why the input leads to corruption]`

**GDB / Sanitiser Evidence:**
```text
Program received signal SIGILL, Illegal instruction.
validate_packet_integrity sentinel_network.c:94        <- reads pkt->magic (uint32_t) from input_stream+23
  #1 old_main sentinel_network.c:176                   <- main loop validates the next packet
  #2 main     sentinel_network.c:198
# packet 1 has length=15, so the next packet starts at offset 8+15=23, which is not 4-byte aligned;
# reading uint32_t magic there is undefined behaviour and UBSan traps (SIGILL) before the compare.
```

**Exploitability Assessment:**
`[Assess the severity and realistic attacker impact]`

---

## 5. Task 4: Code Remediation

### 5.1 Proposed Code-Level Remediations
*[Provide sound, robust C code fixes for every identified vulnerability. Explain how each fix prevents memory corruption without breaking legitimate parsing functionality.]*

#### Patch for Vulnerability 1 (`sentinel_telemetry.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

#### Patch for Vulnerability 2 (`sentinel_telemetry.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

#### Patch for Vulnerability X (`sentinel_payload.c`):
```c
// Provide the corrected C code block or diff
```
**Technical Justification:**
`[Explain how the patch fixes the root cause]`

### 5.2 Regression Verification & Fuzzing Proof
*[Demonstrate that your patched target binaries run cleanly on previously crashing inputs and continue to accept valid seed inputs without errors.]*

```bash
# Demonstrate executing the patched binaries against all triggering crash inputs

```

**Regression Fuzzing Observations:**
`[Document your regression campaign results proving zero new crashes occurred during re-fuzzing]`

---

## 6. Task 5: Proof-of-Concept Exploitation

### 6.1 Target Vulnerability & Security Consequence
*[Specify which critical vulnerability was chosen for exploitation. Describe the intended actionable security consequence beyond a simple crash (e.g. arbitrary memory write, stack leak, control flow hijacking, or state flag overwrite).]*

- **Target Component:** `[e.g. sentinel_telemetry.c / sentinel_payload.c / sentinel_network.c]`
- **Vulnerability Selected:** `[e.g. Format String Arbitrary Write / Stack Buffer Overflow Hijack]`
- **Actionable Exploit Consequence:** `[Describe the tangible exploit objective achieved]`

### 6.2 Memory Layout & Address Analysis
*[Detail the memory state, stack/heap frame layout, resolved target addresses, GDB memory dumps, and endianness considerations.]*

`[Complete this section with stack/memory diagrams and GDB address resolution steps]`

### 6.3 Complete Exploit Script
*[Provide your full, working Python exploit script or shell payload generator.]*

```python
#!/usr/bin/env python3
"""
IFN657 Assignment 2: Proof-of-Concept Exploit Script
Target: [Target component name]
Security Consequence: [Actionable consequence description]
"""

# Insert complete Python exploit script here
```

### 6.4 Reproduction Instructions & Live Bash Evidence
*[Provide step-by-step commands to compile and execute your exploit in standard bash, accompanied by terminal output proving successful exploitation.]*

```bash
# Commands to execute the exploit
# For example, `python3 exploit.py > exploit_payload.bin` then `./target_binary exploit_payload.bin`
```

**Observed Terminal Output & Verification:**
```text
[Paste terminal output proving successful exploit execution]
```