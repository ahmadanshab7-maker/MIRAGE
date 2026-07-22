"""Runtime information collector.

Collects statistics about running processes and services.
Does not collect sensitive process details like command arguments or environment variables.
"""

import os
from pathlib import Path
from typing import Any, Optional


def _read_proc_file(path: str) -> Optional[str]:
    """Safely read a /proc file, returning None if unavailable."""
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def _get_process_list() -> list[dict[str, Any]]:
    """Get basic process information from /proc."""
    processes = []
    
    try:
        proc_entries = os.listdir("/proc")
    except (OSError, PermissionError):
        return processes
    
    for entry in proc_entries:
        if not entry.isdigit():
            continue
        
        pid = int(entry)
        proc_dir = Path(f"/proc/{pid}")
        
        if not proc_dir.exists():
            continue
        
        proc_info: dict[str, Any] = {
            "pid": pid,
            "ppid": None,
            "state": None,
            "comm": None,
            "uid": None,
            "gid": None,
            "threads": None,
            "start_time": None,
        }
        
        # Read stat file
        stat_content = _read_proc_file(f"/proc/{pid}/stat")
        if stat_content:
            # Parse stat - comm is in parentheses
            try:
                # Find the last ')' which ends comm
                last_paren = stat_content.rfind(")")
                if last_paren != -1:
                    comm_part = stat_content[1:last_paren]  # Extract comm without parens
                    proc_info["comm"] = comm_part[:15]  # comm is max 15 chars
                    
                    # Fields after comm
                    after_comm = stat_content[last_paren + 2:].split()
                    if len(after_comm) >= 19:
                        proc_info["state"] = after_comm[0]  # State character
                        proc_info["ppid"] = int(after_comm[1])
                        proc_info["start_time"] = int(after_comm[19])
            except (ValueError, IndexError):
                pass
        
        # Read status file for more details
        status_content = _read_proc_file(f"/proc/{pid}/status")
        if status_content:
            for line in status_content.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == "uids":
                        # Uids: real effective saved fs
                        parts = value.split()
                        if parts:
                            proc_info["uid"] = int(parts[0])
                    elif key == "gids":
                        parts = value.split()
                        if parts:
                            proc_info["gid"] = int(parts[0])
                    elif key == "threads":
                        try:
                            proc_info["threads"] = int(value)
                        except ValueError:
                            pass
        
        processes.append(proc_info)
    
    return processes


def _aggregate_process_stats(processes: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate aggregate statistics from process list."""
    if not processes:
        return {
            "total_processes": 0,
            "unique_comms": 0,
            "by_state": {},
            "zombie_count": 0,
            "thread_total": 0,
            "uid_distribution": {},
        }
    
    unique_comms: set[str] = set()
    state_counts: dict[str, int] = {}
    zombie_count = 0
    thread_total = 0
    uid_counts: dict[int, int] = {}
    
    for proc in processes:
        if proc.get("comm"):
            unique_comms.add(proc["comm"])
        
        state = proc.get("state")
        if state:
            state_counts[state] = state_counts.get(state, 0) + 1
            if state == "Z":
                zombie_count += 1
        
        threads = proc.get("threads")
        if threads:
            thread_total += threads
        
        uid = proc.get("uid")
        if uid is not None:
            uid_counts[uid] = uid_counts.get(uid, 0) + 1
    
    return {
        "total_processes": len(processes),
        "unique_comms": len(unique_comms),
        "by_state": state_counts,
        "zombie_count": zombie_count,
        "thread_total": thread_total,
        "uid_distribution": dict(sorted(uid_counts.items())),
    }


def _check_systemd_services() -> dict[str, Any]:
    """Check systemd service statistics if available."""
    result: dict[str, Any] = {
        "systemd_available": False,
        "total_units": None,
        "active_units": None,
        "failed_units": None,
        "services": {},
    }
    
    # Check if systemd is running
    if not Path("/run/systemd/system").exists():
        return result
    
    result["systemd_available"] = True
    
    # Try to get unit counts from systemctl
    try:
        import subprocess
        output = subprocess.run(
            ["systemctl", "list-units", "--all", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        
        if output.returncode == 0:
            lines = [l for l in output.stdout.splitlines() if l.strip()]
            result["total_units"] = len(lines)
            
            active_count = 0
            failed_count = 0
            service_types: dict[str, int] = {}
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    unit_name = parts[0]
                    load_state = parts[1]
                    active_state = parts[2]
                    sub_state = parts[3]
                    
                    if active_state == "active":
                        active_count += 1
                    if active_state == "failed" or sub_state == "failed":
                        failed_count += 1
                    
                    # Categorize by unit type
                    if unit_name.endswith(".service"):
                        service_types["service"] = service_types.get("service", 0) + 1
                    elif unit_name.endswith(".socket"):
                        service_types["socket"] = service_types.get("socket", 0) + 1
                    elif unit_name.endswith(".target"):
                        service_types["target"] = service_types.get("target", 0) + 1
                    elif unit_name.endswith(".timer"):
                        service_types["timer"] = service_types.get("timer", 0) + 1
                    else:
                        service_types["other"] = service_types.get("other", 0) + 1
            
            result["active_units"] = active_count
            result["failed_units"] = failed_count
            result["services"] = service_types
            
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass
    
    return result


def _check_init_system() -> dict[str, Any]:
    """Detect init system."""
    result: dict[str, Any] = {
        "init_system": None,
        "pid1_comm": None,
    }
    
    # Check PID 1
    try:
        pid1_comm = _read_proc_file("/proc/1/comm")
        if pid1_comm:
            result["pid1_comm"] = pid1_comm
            
            if "systemd" in pid1_comm:
                result["init_system"] = "systemd"
            elif "init" in pid1_comm:
                result["init_system"] = "sysvinit"
            elif "openrc" in pid1_comm:
                result["init_system"] = "openrc"
            elif "runit" in pid1_comm:
                result["init_system"] = "runit"
            elif "s6" in pid1_comm:
                result["init_system"] = "s6"
    except Exception:
        pass
    
    return result


def collect() -> dict[str, Any]:
    """Collect runtime information.
    
    Returns:
        Dictionary containing runtime-level measurements.
    """
    result: dict[str, Any] = {
        "process_statistics": {},
        "service_statistics": {},
        "init_system": {},
        "errors": [],
    }
    
    # Process statistics
    try:
        processes = _get_process_list()
        result["process_statistics"] = _aggregate_process_stats(processes)
    except Exception as e:
        result["errors"].append(f"processes: {str(e)}")
    
    # Service statistics (systemd)
    try:
        result["service_statistics"] = _check_systemd_services()
    except Exception as e:
        result["errors"].append(f"services: {str(e)}")
    
    # Init system detection
    try:
        result["init_system"] = _check_init_system()
    except Exception as e:
        result["errors"].append(f"init: {str(e)}")
    
    return result
