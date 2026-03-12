
Orginal code was not made by me: https://github.com/onkar-omr/HPC-Collection-By-Running-Malaware-inside-LXC-Containers-.git   https://github.com/cryptolok/ASLRay.git
[![Rawsec's CyberSecurity Inventory](http://inventory.raw.pm/img/badges/Rawsec-inventoried-FF5050_flat-square.svg)](http://inventory.raw.pm/tools.html#ASLRay)

# ASLRay + HPC Data Collector
Linux ELF x32/x64 ASLR DEP/NX bypass exploit with stack-spraying, integrated with Hardware Performance Counter (HPC) data collection via `perf stat` inside LXC containers.

![](https://i.imgur.com/mBuqu8J.jpg)

## Quick Start

```bash
git clone https://github.com/Person543/HPC.git
cd HPC
./HPC_data_collector.py
```

That's it. The script will:
1. Check that all dependencies are installed (and tell you what's missing)
2. Compile `test.c` into a vulnerable binary
3. Create an LXC container if one doesn't exist
4. Push the binary + ASLRay.sh into the container
5. Run the ASLRay exploit while collecting HPC data via `perf stat`
6. Parse results into CSV files in `results/`

## Prerequisites

The script checks for these automatically and will tell you exactly what to install if anything is missing:

| Tool | Package | Purpose |
|------|---------|---------|
| gcc | `gcc` | Compile test.c into exploitable binary |
| perf | `linux-tools-$(uname -r) linux-tools-generic` | Hardware performance counter monitoring |
| lxc | `lxc` | Container management tools |
| python3-lxc | `python3-lxc` | Python bindings for LXC |

**If you have sudo:**
```bash
sudo apt-get install -y gcc linux-tools-$(uname -r) linux-tools-generic lxc python3-lxc
```

**If you don't have sudo**, ask your system administrator to install the packages above and:
```bash
# Allow your user to use perf counters
sysctl kernel.perf_event_paranoid=1

# Add your user to the lxc group (for container access)
usermod -aG lxc <your-username>
```

## Usage

### Default mode (ASLRay + HPC collection)
```bash
./HPC_data_collector.py
```
Compiles the bundled `test.c`, runs ASLRay against it inside a container, and collects HPC data. No arguments needed.

### All options
```bash
./HPC_data_collector.py --help
```

| Option | Default | Description |
|--------|---------|-------------|
| `--container` | `new-cont` | Name of LXC container to use |
| `--clone-name` | `tmp-cont` | Name for cloned container |
| `--direct` | off | Direct execution mode (no ASLRay) |
| `--sample-dir` | (none) | Directory of custom binaries to run |
| `--sample-list` | (none) | Text file listing specific sample names |
| `--events` | L1-dcache-load-misses,... | Comma-separated perf events |
| `--result-dir` | `results/` | Output directory for CSV results |
| `--buffer` | 1024 | Buffer size for ASLRay exploit |
| `--shellcode` | (none) | Custom shellcode for ASLRay |
| `--timeout` | 60 | Seconds before killing exploit loop |
| `--allow-network` | off | Skip the internet safety check |

### Examples
```bash
# Default: ASLRay with bundled test binary
./HPC_data_collector.py

# Custom buffer size and timeout
./HPC_data_collector.py --buffer 2048 --timeout 120

# Use your own binaries
./HPC_data_collector.py --sample-dir /path/to/binaries

# Direct execution mode (run binaries without ASLRay)
./HPC_data_collector.py --direct --sample-dir /path/to/binaries

# Custom perf events
./HPC_data_collector.py --events cache-misses,branch-misses,instructions
```

## How It Works

### Architecture
```
Host machine (HPC)
  |
  +-- HPC_data_collector.py
  |     |-- compiles test.c (gcc -z execstack -fno-stack-protector)
  |     |-- creates/clones LXC container
  |     |-- pushes binary + ASLRay.sh into container via base64
  |     |-- runs perf stat monitoring HPC events
  |     |-- parses output to CSV (DataParser.py)
  |
  +-- LXC Container
        |-- /tmp/ASLRay.sh (exploit script)
        |-- /tmp/test (vulnerable binary)
        |-- perf stat collects real CPU hardware counters
```

The container provides software isolation, but the exploit runs on the real CPU hardware. This means `perf stat` captures the actual hardware-level fingerprint of the ASLRay exploit (cache misses, branch mispredictions, TLB misses from stack-spraying), which can be used for exploit detection research.

### HPC Events Collected (default)
- `L1-dcache-load-misses` / `L1-dcache-loads` / `L1-dcache-stores` - L1 data cache
- `L1-icache-load-misses` - L1 instruction cache
- `LLC-load-misses` / `LLC-loads` - Last-level cache
- `branch-loads` - Branch prediction
- `iTLB-load-misses` - Instruction TLB

### Files
| File | Purpose |
|------|---------|
| `HPC_data_collector.py` | Main script - orchestrates everything |
| `Container.py` | LXC container management (create, clone, push files, run commands) |
| `DataParser.py` | Parses perf stat output into CSV |
| `ASLRay.sh` | The ASLR/DEP bypass exploit script |
| `test.c` | Vulnerable C program (buffer overflow target) |

## ASLRay Details

Properties:
* ASLR bypass
* DEP/NX bypass
* Cross-platform
* Minimalistic
* Simplicity
* Unpatchable

Dependencies:
* **Linux 2.6.12+** - would work on any x86-64 Linux-based OS
	- BASH - the whole script

Limitations:
* Stack needs to be executable (-z execstack) for x64
* Binary has to be exploited through arguments locally (not file, socket or input)
* No support for other architectures and OSes (TODO)
* Need to know the buffer limit/size

### How ASLRay works
You might have heard of [Heap Spraying](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/) attack? Well, [Stack Spraying](http://j00ru.vexillium.org/?p=769) is similar, however, it was considered unpractical for most cases, especially [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) on x86-64.

My work will prove the opposite.

For 32-bit, there are 2^32 (4 294 967 296) theoretical addresses, nevertheless, the kernel will allow to control about only half of bits (2^(32/2) = 65 536) for an execution in a virtualized memory, which means that if we control more that 50 000 characters in stack, we are almost sure to point to our shellcode, regardless the address, thanks to kernel redirection and retranslation. According to my tests, even 100 or 10 characters are enough if the called function doesn't contain other variable creations, which will allow ROP-style attack.

This can be achieved using shell variables, which aren't really limited to a specific length, but practical limit is about one hundrer thousand, otherwise it will saturate the TTY.

So, in order to exploit successfully with any shellcode, we need to put a [NOP sled](https://en.wikipedia.org/wiki/NOP_slide) following the shellcode into a shell variable and just exploit the binary with a random address. Note that NOP sled isn't necessary, this is just to universalise the exploit.


In 64-bit system the situation is different, but not so much as of my discovery.

Of course, you wouldn't have to cover all 2^64 possibilities, in fact, the kernel allows only 48 bits, plus a part of them are predictable and static, which left us with about 2^(4x8+5) (137 438 953 472) possibilities.

I have mentioned the shell variables size limit, but there is also a count limit, which appears to be about 10, thus allowing us to stock a 1 000 000 character shellcode, living us with just some tenth of thousand possibilities that can be tested rapidly and automatically. This time however, you will need to bruteforce and use NOP-sleds in order to make things quicker.

That said, ASLR on both 32 and 64-bits can be easily bypassed in few minutes and with few lines of shell...

The DEP/NX on the other hand, can be bypassed on x32 using [return-to-libc](https://www.exploit-db.com/docs/28553.pdf) technique by coupling it with statistical studies of different OSes, more specifically, their ASLR limitations and implementations, which can lead to a successful exploitation for 2 reasons.
The rist one is being ASLR not so random in its choice and having some constants and poor entropy (easy to guess libC address and each OS has its own constants).
The second one is spraying the shell argument for libC into environment (easy to find and pass it to libC).

To conclude, DEP/NX on 32-bits is weakened because of ASLR.

A more detailed description can be found in Hakin9-12-14 [issue](https://hakin9.org/download/hakin9-open-open-source-tools/).

### Running ASLRay standalone

If you want to run ASLRay without the HPC data collector:
```bash
gcc -z execstack -fno-stack-protector test.c -o test
chmod u+x ASLRay.sh
source ASLRay.sh test 1024
source ASLRay.sh test 1024 \x31\x80...your_shellcode_here
```

For 32-bit:
```bash
gcc -m32 -z execstack -fno-stack-protector test.c -o test32
source ASLRay.sh test32 1024
```

**!!! WARNING !!!** The PoC scripts will modify your /etc/passwd and change permissions of /etc/shadow, VM execution advised:
```bash
chmod u+x PoC.sh
source PoC.sh
grep ALI /etc/passwd
```

To prove that even environmental variable isn't necessary for Debian x32:
```bash
chmod u+x PoC2.sh
source PoC2.sh
```

In Debian 10, this issue was partially patched, notably due to AppArmor.

#### Notes

Always rely on multiple protections and not on a single one.

We need new system security mechanisms.

> "From where we stand the rain seems random. If we could stand somewhere else, we would see the order in it. "

Tony Hillerman, *Coyote Waits*
