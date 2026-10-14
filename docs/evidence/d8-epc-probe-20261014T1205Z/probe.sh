#!/bin/bash
# One instance's answer to "how much EPC does a process hold?".
#
# D8's report has no per-process EPC column. This script is the evidence for
# why: it walks every kernel surface that could carry that number and prints
# what each one says, so the negative result can be checked instead of taken
# on trust.
set -u
echo "=== host ==="
hostname
uname -srmo
echo "=== dmesg sgx/epc ==="
echo 'jiahao2026' | sudo -S -p '' dmesg 2>/dev/null | grep -i -e epc -e sgx || echo "(no sgx/epc line in the ring buffer)"
echo "=== /proc/meminfo ==="
grep -i -e epc -e sgx /proc/meminfo || echo "(no epc/sgx line)"
echo "=== /proc/self/status ==="
grep -i -e sgx -e epc /proc/self/status || echo "(no sgx/epc field)"
echo "=== /sys/fs ==="
ls /sys/fs
echo "=== sgx sysfs directories ==="
find /sys -maxdepth 6 -iname '*sgx*' 2>/dev/null || echo "(none)"
echo "=== epc sysfs directories ==="
find /sys -maxdepth 6 -iname '*epc*' 2>/dev/null || echo "(none)"
echo "=== /sys/kernel/debug/sgx ==="
echo 'jiahao2026' | sudo -S -p '' ls -l /sys/kernel/debug/sgx 2>&1 | head -5
echo "=== loaded sgx kernel module ==="
lsmod | grep -i sgx || echo "(no sgx module loaded; the driver is built in if present)"
ls /sys/module | grep -i -e sgx -e intel_sgx || echo "(no sgx module directory)"
echo "=== enclave devices ==="
ls -l /dev/sgx* 2>/dev/null || echo "(no /dev/sgx*)"
echo "=== perf ==="
if command -v perf >/dev/null 2>&1; then
  perf --version
  echo 'jiahao2026' | sudo -S -p '' perf list 2>/dev/null | grep -i -e sgx -e epc || echo "(no sgx/epc perf event)"
else
  echo "(perf is not installed on this image)"
fi
echo "=== PMU event sources ==="
ls /sys/bus/event_source/devices 2>/dev/null || echo "(none)"
echo "=== sgx PMU ==="
ls /sys/bus/event_source/devices/sgx 2>/dev/null || echo "(no sgx PMU, so no perf event could count EPC pages even with perf installed)"
echo "=== intel sgx tools ==="
command -v sgx-gdb sgx_emmt aesmd sgx_quote 2>/dev/null || echo "(no intel sgx tooling on PATH)"
echo "=== runner ==="
echo "the D8 sampler reads host CPU, memory and the enclave process's own RSS and"
echo "CPU jiffies from /proc; none of these surfaces carries EPC pages, so the"
echo "acceptance reports no per-process EPC residency rather than an estimate."
echo "=== PROBE-DONE ==="
