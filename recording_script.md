unset AFL_USE_ASAN AFL_USE_UBSAN

# Start recording
asciinema rec Group_01.cast
 
echo "==== TASK 0: TEAM IDENTIFICATION ===="
echo "=== IFN657 ASSIGNMENT 2 TEAM IDENTIFICATION ==="
echo "Group: Group_01 | Members: n12379417 (Claire), n12284181 (Rachel), n12224774 (Kaito)"
whoami && hostname
uname -a
afl-fuzz -v && gcc --version
 
# Fuzzing & exploit walkthrough (demonstrate all practical components)

## --- Compilation & Target Environment Setup ---
echo "==== TASK 1: SETUP & COMPILATION ===="

cd sentinel_telemetry
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_telemetry_nosan sentinel_telemetry.c

cd ../sentinel_payload
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_payload_nosan sentinel_payload.c

cd ../sentinel_network
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_network_nosan sentinel_network.c

---

export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1

cd ../sentinel_telemetry
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_telemetry_asan_ubsan sentinel_telemetry.c

cd ../sentinel_payload
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_payload_asan_ubsan sentinel_payload.c

cd ../sentinel_network
afl-clang-fast -m32 -std=c99 -g -w -o sentinel_network_asan_ubsan sentinel_network.c

---

cd ..

unset AFL_USE_ASAN

unset AFL_USE_UBSAN

export AFL_USE_MSAN=1

cd sentinel_payload
afl-clang-fast -std=c99 -g -w -o sentinel_payload_msan sentinel_payload.c

cd ../sentinel_network
afl-clang-fast -std=c99 -g -w -o sentinel_network_msan sentinel_network.c


## --- Fuzzing ---
echo "==== TASK 2: FUZZING EXECUTION ===="
cd ../sentinel_telemetry
// Baseline fuzzing:
afl-fuzz -i seeds -o findings/fuzz_out_nosan_demo ./sentinel_telemetry_nosan @@
Ctrl + C

// Main fuzzer:
// afl-fuzz -i seeds -o fuzz_out_parallel -M main -x dict ./sentinel_telemetry_nosan @@
// Secondary fuzzer:
// afl-fuzz -i seeds -o fuzz_out_parallel -S secondary -x dict ./sentinel_telemetry_nosan @@

// Sanitizer-guided fuzzing:
afl-fuzz -i seeds -o findings/fuzz_out_asan_ubsan_demo -m none ./sentinel_telemetry_asan_ubsan @@
Ctrl + C to stop


## --- Crash triage: Reproduce at least two distinct crashes using GDB or sanitisers ---
echo "==== TASK 3: VULNERABILITY ANALYSIS ===="
cd ../sentinel_payload
./sentinel_payload_asan_ubsan crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_asan_ubsan crash_analysis/heap-use-after-free01.bin

## --- Remediation ---

echo "==== TASK 4: CODE REMEDIATION ===="

./sentinel_payload_remediated crash_analysis/heap-buffer-overflow01.bin
./sentinel_payload_remediated crash_analysis/heap-use-after-free01.bin


## --- Proof-of-concept exploit ---
echo "====TASK 5: PROOF-OF-CONCEPT EXPLOITATION ===="
cd ../sentinel_network

python3 exploits/exploit.py
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
./sentinel_network_original exploits/exploit.bin


# Stop recording
exit

# Replay recording
asciinema play Group_01.cast
