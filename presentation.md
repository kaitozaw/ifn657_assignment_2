# 0. Setup

```bash
lima
cd ~/ifn657/assignments/assignment_2/
```

# 1. Fuzzing Methodology

```bash
# Show Group_01.md
```

# 2. Key Vulnerability Findings

```bash
cd sentinel_payload/

# Output the seed file.
cat crash_analysis/heap-buffer-overflow01.bin

# Demonstrate program flow with GDB (Prepare this output early).
gdb --args ./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
break 113
run
next
next
next

# Alternative: Print crash log output.
cat crash_logs/out_nosan_crashes_id_000003_sig_11_src_000001_time_17339_execs_349023_op_havoc_rep_7.log

cd ..
```

# 3. Exploit Demonstration

```bash
cd sentinel_network/
cat exploits/exploit.py
python3 exploits/exploit.py
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
./sentinel_network_original exploits/exploit.bin
echo $?
# Show Group_01.md
cd ..
```

# 4. Remediation & Reflection

```bash
cd sentinel_payload/

# Display sentinel_payload_remediated.c or open the file in VSC.
cat sentinel_payload_remediated.c

# Display existing fuzzing results.
cat out/remediated/default/fuzzer_stats

# Alternative: Demonstrate fuzzing on sentinel_payload's remediated source code.
echo core | sudo tee /proc/sys/kernel/core_pattern
afl-fuzz -i seeds -o out -x sentinel_payload.dict -m none ./sentinel_payload_remediated @@
```