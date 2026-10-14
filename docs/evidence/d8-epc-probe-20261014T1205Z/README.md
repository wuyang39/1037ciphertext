# EPC probe: why D8 carries no per-process EPC column

D8's resource table reports host CPU, host memory, the enclave process's own
RSS and the enclave process's own CPU jiffies, all read from `/proc`. It has no
EPC residency column, and this bundle is the evidence for that: on all three
acceptance instances there is no surface that accounts EPC pages per process.

The probe was run on each instance at commit
`b1f87bae5b9822d704e1b17ca924c7fbebc45bec` with `probe.sh` (shipped here) and
the raw output of each run is beside it:

| instance | role | address | output |
| --- | --- | --- | --- |
| `iZuf6bjvfplpwleemaipwmZ` | P0 | `106.15.28.144` | `p0-106.15.28.144.txt` |
| `iZuf6bd6qnhgtveg5khyf1Z` | P1 | `139.224.54.254` | `p1-139.224.54.254.txt` |
| `iZuf6bd6qnhgtveg5khygdZ` | P2 | `8.133.240.216` | `p2-8.133.240.216.txt` |

## What each surface says

- **The ring buffer reports the section, not the process.** `dmesg` carries
  `sgx: EPC section 0x240000000-0x42fffffff`, which is the size of the
  enclave page cache the platform reserved at boot. It says nothing about how
  much of it one process holds.
- **`/proc/meminfo` has no EPC or SGX line.** The kernel accounts EPC outside
  the virtual-memory counters it publishes there.
- **`/proc/<pid>/status` has no SGX or EPC field.** Neither does any other
  `/proc` file: the per-process accounting the column would need does not
  exist in this kernel.
- **The driver exposes no debugfs directory.** `/sys/kernel/debug/sgx` is
  absent, and no `sgx` directory exists anywhere under `/sys/kernel`.
- **There is no SGX PMU.** `/sys/bus/event_source/devices/sgx` does not exist,
  so even with `perf` installed there would be no event to count EPC pages
  with. On this image `perf` is not installed either.
- **The only SGX entries under `/sys` are the character devices.** They are
  `/sys/class/misc/sgx_enclave` and `/sys/class/misc/sgx_provision`, which
  carry no counters. `/sys/class/pci_epc` is the PCI endpoint-controller class
  and has nothing to do with enclave pages.

## What this means for the acceptance

The EPC budget is still what the geometry was chosen against: the platform
reserved a 512 MiB EPC section, and the one-layer, 1028-candidate probe fits
inside it. What cannot be taken from these instances is a *number* for one
process's residency, so `docs/d8-acceptance.md` and
`docs/d8-ablation-acceptance.md` do not carry one, and the conclusion map
records the gap as still open rather than filling it with an estimate.

Closing it would need a host whose kernel publishes the accounting (a
debugfs or sysfs interface from a different SGX driver build, or an SGX PMU
the perf subsystem could sample). Nothing in this repository can add it.
