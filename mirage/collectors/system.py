"""System information collector.

Collects read-only system-level information from /proc, /sys, and standard APIs.
Does not execute active probes or collect sensitive data.
"""

import os
import platform
import re
from pathlib import Path
from typing import Any, Optional


def _read_proc_file(path: str) -> Optional[str]:
    """Safely read a /proc or /sys file, returning None if unavailable."""
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def _read_proc_lines(path: str) -> list[str]:
    """Safely read lines from a /proc or /sys file."""
    content = _read_proc_file(path)
    if content is None:
        return []
    return [line for line in content.splitlines() if line]


def _parse_cpuinfo() -> dict[str, Any]:
    """Parse /proc/cpuinfo for CPU characteristics.
    
    Returns basic CPU architecture and resource measurements.
    Does NOT collect CPU flags (fingerprinting concern).
    """
    result: dict[str, Any] = {
        "model_name": None,
        "cpu_cores": 0,
        "siblings": 0,
        "vendor_id": None,
        "cpu_mhz_min": None,
        "cpu_mhz_max": None,
        "cache_size_kb": None,
        # flags intentionally excluded - contributes to machine fingerprinting
    }
    
    content = _read_proc_file("/proc/cpuinfo")
    if not content:
        return result
    
    processors = re.split(r"\n(?=\w+:)", content)
    core_count = 0
    mhz_values: list[float] = []
    
    for section in processors:
        if "processor" in section.lower():
            core_count += 1
        
        for line in section.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == "model name":
                    result["model_name"] = value
                elif key == "vendor id":
                    result["vendor_id"] = value
                elif key == "cache size":
                    match = re.search(r"(\d+)", value)
                    if match:
                        result["cache_size_kb"] = int(match.group(1))
                # flags/features intentionally skipped - not needed for environmental characterization
                elif key in ("cpu mhz", "cpu MHz"):
                    try:
                        mhz_values.append(float(value))
                    except ValueError:
                        pass
    
    result["cpu_cores"] = core_count
    # Count siblings from physical cores perspective
    result["siblings"] = core_count  # Simplified; accurate sibling count needs more parsing
    # No flags collected
    
    if mhz_values:
        result["cpu_mhz_min"] = min(mhz_values)
        result["cpu_mhz_max"] = max(mhz_values)
    
    return result


def _parse_meminfo() -> dict[str, Any]:
    """Parse /proc/meminfo for RAM characteristics."""
    result: dict[str, Any] = {
        "total_kb": None,
        "free_kb": None,
        "available_kb": None,
        "buffers_kb": None,
        "cached_kb": None,
    }
    
    content = _read_proc_file("/proc/meminfo")
    if not content:
        return result
    
    for line in content.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            match = re.search(r"(\d+)", value)
            if match:
                val = int(match.group(1))
                if key == "memtotal":
                    result["total_kb"] = val
                elif key == "memfree":
                    result["free_kb"] = val
                elif key == "memavailable":
                    result["available_kb"] = val
                elif key == "buffers":
                    result["buffers_kb"] = val
                elif key == "cached":
                    result["cached_kb"] = val
    
    return result


def _get_storage_info() -> dict[str, Any]:
    """Get storage/filesystem statistics from statvfs.
    
    Returns storage information grouped by underlying filesystem device.
    Multiple mountpoints on the same filesystem are reported together
    to avoid presenting them as independent storage devices.
    """
    result: dict[str, Any] = {
        "filesystems": [],
    }
    
    mountpoints = ["/", "/home", "/tmp", "/var"]
    
    # Track seen filesystem devices by (device_id) to group mounts
    # We use os.statvfs().f_fsid as a filesystem identifier
    # Note: This is NOT a persistent identifier across reboots
    seen_filesystems: dict[int, dict[str, Any]] = {}
    mount_to_fs: dict[str, int] = {}  # Maps mountpoint to filesystem index
    
    for mountpoint in mountpoints:
        try:
            stat = os.statvfs(mountpoint)
            fs_id = stat.f_fsid  # Filesystem ID (not persistent across reboots)
            
            total_gb = (stat.f_blocks * stat.f_frsize) / (1024**3)
            free_gb = (stat.f_bfree * stat.f_frsize) / (1024**3)
            available_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            used_gb = total_gb - free_gb
            
            mount_info = {
                "path": mountpoint,
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "available_gb": round(available_gb, 2),
                "percent_used": round((1 - stat.f_bavail / stat.f_blocks) * 100, 1) if stat.f_blocks else None,
            }
            
            if fs_id in seen_filesystems:
                # This mountpoint is on an already-seen filesystem
                # Add it as an additional mount point for this filesystem
                seen_filesystems[fs_id]["mount_points"].append(mountpoint)
            else:
                # New filesystem - create entry
                fs_index = len(seen_filesystems)
                seen_filesystems[fs_id] = {
                    "filesystem_index": fs_index,
                    "primary_mount": mountpoint,
                    "mount_points": [mountpoint],
                    "total_gb": round(total_gb, 2),
                    "used_gb": round(used_gb, 2),
                    "free_gb": round(free_gb, 2),
                    "available_gb": round(available_gb, 2),
                    "percent_used": round((1 - stat.f_bavail / stat.f_blocks) * 100, 1) if stat.f_blocks else None,
                }
                mount_to_fs[mountpoint] = fs_index
                
        except (OSError, PermissionError):
            continue
    
    # Convert to list output format
    for fs_id, fs_data in seen_filesystems.items():
        result["filesystems"].append({
            "filesystem_index": fs_data["filesystem_index"],
            "primary_mount": fs_data["primary_mount"],
            "mount_points": sorted(fs_data["mount_points"]),
            "total_gb": fs_data["total_gb"],
            "used_gb": fs_data["used_gb"],
            "free_gb": fs_data["free_gb"],
            "available_gb": fs_data["available_gb"],
            "percent_used": fs_data["percent_used"],
        })
    
    return result


def _get_uptime() -> Optional[float]:
    """Get system uptime in seconds from /proc/uptime."""
    content = _read_proc_file("/proc/uptime")
    if content:
        parts = content.split()
        if parts:
            try:
                return float(parts[0])
            except ValueError:
                pass
    return None


def _detect_virtualization() -> dict[str, Any]:
    """Detect virtualization type from safe read-only sources.
    
    Returns:
        Dictionary with hypervisor, virtualization_type, and source.
        
    Notes:
        - virtualization_type is "vm", "container", or "unknown"
        - "bare-metal" is NEVER asserted from absence of evidence
        - Positive evidence is required to assert vm or container
    """
    result: dict[str, Any] = {
        "hypervisor": None,
        "virtualization_type": "unknown",  # Default to unknown, not bare-metal
        "source": None,
    }
    
    # Check /sys/class/dmi for VM indicators
    bios_vendor = _read_proc_file("/sys/class/dmi/id/bios_vendor")
    sys_vendor = _read_proc_file("/sys/class/dmi/id/sys_vendor")
    product_name = _read_proc_file("/sys/class/dmi/id/product_name")
    chassis_type = _read_proc_file("/sys/class/dmi/id/chassis_type")
    
    vm_indicators = {
        "VMware": ["VMware"],
        "VirtualBox": ["innotek GmbH", "Oracle Corporation", "VirtualBox"],
        "KVM": ["QEMU", "KVM"],
        "Hyper-V": ["Microsoft Corporation"],
        "Xen": ["Xen"],
        "AWS": ["Amazon EC2"],
        "GCP": ["Google Compute Engine"],
        "Azure": ["Microsoft Azure"],
    }
    
    detected = None
    source_field = None
    
    for vendor_str in [bios_vendor, sys_vendor, product_name]:
        if vendor_str:
            for hypervisor, indicators in vm_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in vendor_str.lower():
                        detected = hypervisor
                        source_field = "dmi"
                        break
                if detected:
                    break
        if detected:
            break
    
    # Check /proc/cpuinfo for hypervisor flag (read directly, not from parsed flags)
    cpuinfo_content = _read_proc_file("/proc/cpuinfo")
    if cpuinfo_content and "hypervisor" in cpuinfo_content.lower():
        if not detected:
            detected = "Unknown (hypervisor flag present)"
        source_field = "cpuinfo_flag"
    
    # Check container detection
    if _is_container():
        detected = "Container"
        source_field = "container_detection"
    
    result["hypervisor"] = detected
    # Only set virtualization_type if we have positive evidence
    if detected == "Container":
        result["virtualization_type"] = "container"
    elif detected is not None:
        result["virtualization_type"] = "vm"
    else:
        # Absence of evidence means unknown, NOT bare-metal
        result["virtualization_type"] = "unknown"
    result["source"] = source_field
    
    return result


def _is_container() -> bool:
    """Check if running inside a container (Docker, LXC, etc.)."""
    # Check for .dockerenv
    if Path("/.dockerenv").exists():
        return True
    
    # Check cgroup for container patterns
    cgroup = _read_proc_file("/proc/1/cgroup")
    if cgroup:
        if "docker" in cgroup or "lxc" in cgroup or "kubepods" in cgroup:
            return True
    
    # Check for container-specific mounts
    if Path("/run/.containerenv").exists():
        return True
    
    return False


def collect() -> dict[str, Any]:
    """Collect all system information.
    
    Returns:
        Dictionary containing system-level measurements.
        
    Notes:
        - Hostname is intentionally NOT collected (privacy concern)
    """
    result: dict[str, Any] = {
        "os": {},
        "kernel": {},
        # hostname intentionally excluded - identifies specific machines
        "architecture": {},
        "cpu": {},
        "memory": {},
        "storage": {},
        "uptime_seconds": None,
        "virtualization": {},
        "errors": [],
    }
    
    # OS information
    try:
        result["os"] = {
            "name": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            # node (hostname) intentionally excluded for privacy
        }
        
        # Try to get Linux distribution info
        try:
            distro_info = platform.freedesktop_os_release()
            result["os"]["distribution"] = {
                "id": distro_info.get("ID"),
                "name": distro_info.get("NAME"),
                "version_id": distro_info.get("VERSION_ID"),
                "pretty_name": distro_info.get("PRETTY_NAME"),
            }
        except (OSError, AttributeError):
            # Fallback for older Python versions
            try:
                lsb = _read_proc_file("/etc/lsb-release")
                if lsb:
                    dist = {}
                    for line in lsb.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            dist[k] = v.strip('"')
                    result["os"]["distribution"] = dist
            except Exception:
                pass
    except Exception as e:
        result["errors"].append(f"os_info: {str(e)}")
    
    # Kernel information
    try:
        uname = os.uname()
        result["kernel"] = {
            "sysname": uname.sysname,
            # nodename (hostname) intentionally excluded for privacy
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
        }
    except Exception as e:
        result["errors"].append(f"kernel_info: {str(e)}")
    
    # Architecture
    try:
        result["architecture"] = {
            "bits": platform.architecture()[0] or None,
            "linkage": platform.architecture()[1] or None,
            "machine": platform.machine() or None,
            "processor": platform.processor() or None,
        }
    except Exception as e:
        result["errors"].append(f"architecture: {str(e)}")
    
    # CPU characteristics (no flags collected)
    try:
        result["cpu"] = _parse_cpuinfo()
    except Exception as e:
        result["errors"].append(f"cpu: {str(e)}")
    
    # Memory characteristics
    try:
        result["memory"] = _parse_meminfo()
    except Exception as e:
        result["errors"].append(f"memory: {str(e)}")
    
    # Storage/filesystem characteristics
    try:
        result["storage"] = _get_storage_info()
    except Exception as e:
        result["errors"].append(f"storage: {str(e)}")
    
    # Uptime
    try:
        result["uptime_seconds"] = _get_uptime()
    except Exception as e:
        result["errors"].append(f"uptime: {str(e)}")
    
    # Virtualization information
    try:
        result["virtualization"] = _detect_virtualization()
    except Exception as e:
        result["errors"].append(f"virtualization: {str(e)}")
    
    return result
