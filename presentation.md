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
cat exploits/exploit_gdb.py
python3 exploits/exploit_gdb.py
xxd exploits/exploit_gdb.bin

gdb sentinel_network_original
break dispatch_telecommand
run exploits/exploit_gdb.bin

continue                                # dispatch 1st packet (type=2)
continue                                # dispatch 2nd packet (type=2)
continue                                # dispatch 3rd packet (type=2)
x/48xw 0x5655b570                       # show heap memory layout
continue                                # dispatch 4th packet (type=3)
x/48xw 0x5655b570                       # show heap memory layout
continue                                # dispatch 5th packet (type=2)
x/48xw 0x5655b570                       # show heap memory layout
continue                                # dispatch 6th packet (type=2)
break sentinel_network_original.c:137   # stop right after final dispatch
continue                                # dispatch 7th packet (type=2)
x/48xw 0x5655b570                       # show heap memory layout
p $ebp                                  # show base pointer value
x/4xw 0xffffce50                        # show stack memory layout
p &exit                                 # show exit address
continue

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