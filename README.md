# MIRAGE v0.1 - Passive Linux Environment Profiler

**MIRAGE** is a measurement instrument for cybersecurity research studying environmental realism and deception. It collects read-only environmental measurements from Linux systems and saves them as structured JSON.

## ⚠️ Important Disclaimers

**MIRAGE v0.1 is NOT:**
- A honeypot detector
- A sandbox detection tool
- A malware anti-analysis tool
- An authenticity/deception scoring system

**Key principles:**
1. **Virtualization is NOT evidence of deception.** Many legitimate systems run in VMs or containers.
2. **Sparse activity is NOT evidence of deception.** Newly provisioned systems naturally have minimal history.
3. **No authenticity score exists in v0.1.** This tool only measures; it does not interpret or classify.
4. **The collected dataset will be used for controlled experiments.** Future research will analyze measurement patterns under known conditions.

## Installation

```bash
# Clone the repository
git clone https://github.com/mirage-profiler/mirage.git
cd mirage

# Install in development mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Usage

### Basic usage (output to stdout)
```bash
python -m mirage.cli
```

### Save snapshot to file
```bash
python -m mirage.cli --output snapshot.json
```

### Run specific collectors
```bash
python -m mirage.cli --collectors system,network --output basic.json
```

### Skip privacy-sensitive collectors
```bash
python -m mirage.cli --no-users --no-filesystem --output minimal.json
```

### Add notes to metadata
```bash
python -m mirage.cli --notes "Fresh Debian 12 VM" --output vm1.json
```

### View help
```bash
python -m mirage.cli --help
```

## Collectors

MIRAGE v0.1 includes six passive collectors:

### 1. System Collector (`system`)
Collects read-only system information from `/proc`, `/sys`, and standard Python APIs:
- OS/distribution information (name, version, codename)
- Kernel information (sysname, release, version)
- Hostname
- Architecture (bits, machine type, processor)
- CPU characteristics (model, cores, flags, frequency range)
- RAM characteristics (total, free, available, buffers, cached)
- Storage/filesystem statistics (mount points, capacity, usage)
- Uptime (seconds since boot)
- Virtualization indicators (from DMI, CPU flags, container detection)

### 2. Users Collector (`users`)
Collects aggregate statistics about local accounts:
- Total account count
- System vs regular account counts
- UID range
- Shell types in use
- Home directory statistics (existence, file/dir counts, aggregate size)
- File age distribution in home directories
- Login history file metadata (existence, size of wtmp, lastlog, btmp)

**Privacy note:** Does NOT collect usernames, passwords, UIDs/GIDs individually, home directory paths, or any file contents.

### 3. Filesystem Collector (`filesystem`)
Collects aggregate filesystem statistics from common directories:
- File and directory counts per path
- Symlink counts
- Total size in bytes
- File type distribution (text, script, binary, archive, log, other)
- Extension frequency (top 20 extensions)
- File age distribution (min/max/median/mean age, counts by time period)

**Scanned paths:** `/etc`, `/usr/bin`, `/usr/lib`, `/var/log`, `/tmp`, `/home`, `/opt`, `/srv`

**Privacy note:** Does NOT collect file names, paths, or contents. Only aggregate statistics.

### 4. Software Collector (`software`)
Collects package manager information:
- Primary package manager detection (dpkg, rpm, pacman)
- Package counts (total, installed, essential)
- Package status distribution (half-installed, config-files, etc.)
- Packages by priority and section
- Additional software sources (Flatpak, Snap, AppImage)

### 5. Runtime Collector (`runtime`)
Collects statistics about running processes and services:
- Total process count
- Unique process names (comm values)
- Process state distribution (running, sleeping, zombie, etc.)
- Thread count totals
- UID distribution (aggregate counts per UID)
- Init system detection (systemd, sysvinit, etc.)
- Systemd service statistics (unit counts by type and state)

**Privacy note:** Does NOT collect command-line arguments, environment variables, or full process details.

### 6. Network Collector (`network`)
Collects network configuration metadata:
- Interface statistics (RX/TX bytes, packets, errors, dropped)
- Interface properties (MAC address, MTU, operstate, link speed)
- Routing table entries (destination, gateway, netmask, interface)
- DNS configuration (nameservers, search domains, options)
- ARP cache entry count
- Network management tools detected (NetworkManager, systemd-networkd)

**Privacy note:** Does NOT scan the network, contact external systems, or capture traffic.

## Output Format

The output is a JSON document with the following structure:

```json
{
  "schema_version": "1.0.0",
  "metadata": {
    "collected_at": "2024-01-15T10:30:00+00:00",
    "collector_name": "mirage",
    "collector_version": "0.1.0",
    "hostname": "example-host",
    "notes": null
  },
  "collectors": {
    "system": { ... },
    "users": { ... },
    "filesystem": { ... },
    "software": { ... },
    "runtime": { ... },
    "network": { ... }
  },
  "errors": []
}
```

## Privacy and Safety

MIRAGE v0.1 is designed with privacy in mind. It explicitly does NOT collect:
- File contents
- Passwords or credentials
- Tokens or private keys
- Browser history or cookies
- Document contents
- Command history contents
- Individual file names or paths (only aggregates)
- Network traffic

All collectors use read-only interfaces (`/proc`, `/sys`, standard APIs) and tolerate permission restrictions gracefully.

## Portability

MIRAGE v0.1 targets Linux systems and handles:
- Different distributions (Debian, Ubuntu, RHEL, Fedora, Arch, etc.)
- Containers (Docker, LXC, Podman)
- Virtual machines (KVM, VMware, VirtualBox, Hyper-V, cloud instances)
- WSL (Windows Subsystem for Linux)
- Systems with restricted permissions

Missing or unavailable data is represented as `null` or empty structures rather than causing failures.

## Development

### Running tests
```bash
pytest
```

### Code structure
```
mirage/
├── __init__.py          # Package initialization, version
├── cli.py               # Command-line interface
├── collectors/
│   ├── __init__.py
│   ├── system.py        # OS, kernel, CPU, memory, storage, virtualization
│   ├── users.py         # Account and home directory statistics
│   ├── filesystem.py    # File/dir counts, age distributions
│   ├── software.py      # Package manager information
│   ├── runtime.py       # Process and service statistics
│   └── network.py       # Interface, routing, DNS configuration
└── models/
    ├── __init__.py
    └── snapshot.py      # Snapshot class for structured output
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Research Context

MIRAGE is part of ongoing cybersecurity research into environmental realism. The goal is to understand how passive observations can distinguish between naturally-used computing environments and deliberately constructed ones, and to determine where increasing environmental fidelity makes such classification unreliable.

This tool provides the measurement foundation for controlled experiments. It does not make any claims about what the measurements mean—that analysis belongs to future research phases.
