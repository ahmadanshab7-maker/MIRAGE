"""Users and account information collector.

Collects read-only statistics about local accounts and home directories.
Does not collect passwords, credentials, or sensitive user data.
"""

import os
import pwd
import grp
from pathlib import Path
from typing import Any, Optional


def _safe_getgrgid(gid: int) -> Optional[str]:
    """Safely get group name by GID."""
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return None


def _get_login_history_stats() -> dict[str, Any]:
    """Get aggregate statistics from login history files if available."""
    result: dict[str, Any] = {
        "wtmp_exists": False,
        "wtmp_size_bytes": None,
        "lastlog_exists": False,
        "lastlog_size_bytes": None,
        "btmp_exists": False,
        "btmp_size_bytes": None,
    }
    
    wtmp_path = Path("/var/log/wtmp")
    lastlog_path = Path("/var/log/lastlog")
    btmp_path = Path("/var/log/btmp")
    
    if wtmp_path.exists():
        result["wtmp_exists"] = True
        try:
            result["wtmp_size_bytes"] = wtmp_path.stat().st_size
        except (OSError, PermissionError):
            pass
    
    if lastlog_path.exists():
        result["lastlog_exists"] = True
        try:
            result["lastlog_size_bytes"] = lastlog_path.stat().st_size
        except (OSError, PermissionError):
            pass
    
    if btmp_path.exists():
        result["btmp_exists"] = True
        try:
            result["btmp_size_bytes"] = btmp_path.stat().st_size
        except (OSError, PermissionError):
            pass
    
    return result


def _get_uid_range() -> dict[str, Any]:
    """Read configured UID range from /etc/login.defs if available.
    
    Returns:
        Dictionary with uid_min, uid_max, and source information.
        If not available, returns None values with appropriate source.
    """
    result: dict[str, Any] = {
        "uid_min": None,
        "uid_max": None,
        "source": None,
    }
    
    login_defs_path = Path("/etc/login.defs")
    if not login_defs_path.exists():
        result["source"] = "unavailable"
        return result
    
    try:
        content = login_defs_path.read_text()
        uid_min_found = None
        uid_max_found = None
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0].upper()
                value = parts[1]
                
                if key == "UID_MIN":
                    try:
                        uid_min_found = int(value)
                    except ValueError:
                        pass
                elif key == "UID_MAX":
                    try:
                        uid_max_found = int(value)
                    except ValueError:
                        pass
        
        if uid_min_found is not None or uid_max_found is not None:
            result["uid_min"] = uid_min_found
            result["uid_max"] = uid_max_found
            result["source"] = "/etc/login.defs"
        else:
            result["source"] = "not_configured"
            
    except (OSError, PermissionError):
        result["source"] = "unreadable"
    
    return result


def collect() -> dict[str, Any]:
    """Collect user and account information.
    
    Returns:
        Dictionary containing user-level measurements.
        
    Notes:
        - Account classification (system vs regular) uses host-configured UID range
          from /etc/login.defs when available.
        - If UID range is not configured, classification is marked as unavailable
          rather than assuming a distribution-specific threshold.
        - Home directory traversal:
          * Never follows symlinks
          * Uses lstat() for size (apparent size, not allocated blocks)
          * Counts only regular files for size calculations
          * Excludes special files (devices, sockets, FIFOs) from size
          * Reports entries_examined, permission errors, and truncation state
    """
    result: dict[str, Any] = {
        "account_statistics": {},
        "home_directory_statistics": {},
        "login_history_metadata": {},
        "errors": [],
    }
    
    # Get configured UID range
    uid_range = _get_uid_range()
    uid_min_config = uid_range["uid_min"]
    uid_max_config = uid_range["uid_max"]
    
    # Account statistics
    try:
        accounts = []
        uid_min = None
        uid_max = None
        system_accounts = 0
        regular_accounts = 0
        unclassifiable_accounts = 0
        
        # Read all password entries
        for entry in pwd.getpwall():
            uid = entry.pw_uid
            gid = entry.pw_gid
            home = entry.pw_dir
            shell = entry.pw_shell
            gecos = entry.pw_gecos
            
            account_info = {
                "uid": uid,
                "gid": gid,
                "group_name": _safe_getgrgid(gid),
                "home": home,
                "shell": shell,
                "has_gecos": bool(gecos and gecos.strip()),
            }
            accounts.append(account_info)
            
            # Categorize accounts using configured UID range
            if uid_min_config is not None:
                # Use host-configured threshold
                if uid < uid_min_config:
                    system_accounts += 1
                else:
                    regular_accounts += 1
            else:
                # Cannot classify without configured range
                unclassifiable_accounts += 1
            
            # Track UID range
            if uid_min is None or uid < uid_min:
                uid_min = uid
            if uid_max is None or uid > uid_max:
                uid_max = uid
        
        account_stats: dict[str, Any] = {
            "total_count": len(accounts),
            "uid_min": uid_min,
            "uid_max": uid_max,
            "shells": list(set(acc["shell"] for acc in accounts if acc["shell"])),
            "unique_gids": len(set(acc["gid"] for acc in accounts)),
            "uid_policy": {
                "source": uid_range["source"],
                "uid_min": uid_min_config,
                "uid_max": uid_max_config,
            },
        }
        
        # Only include classification counts if we have a configured range
        if uid_min_config is not None:
            account_stats["system_account_count"] = system_accounts
            account_stats["regular_account_count"] = regular_accounts
        else:
            # Mark classification as unavailable
            account_stats["system_account_count"] = None
            account_stats["regular_account_count"] = None
            account_stats["classification_unavailable_reason"] = (
                "UID_MIN not configured in /etc/login.defs"
            )
        
        result["account_statistics"] = account_stats
        
        # Home directory statistics
        home_dirs = [acc["home"] for acc in accounts if acc["home"]]
        existing_homes = []
        missing_homes = 0
        
        total_files = 0
        total_dirs = 0
        total_size_bytes = 0
        oldest_mtime = None
        newest_mtime = None
        permission_denied_count = 0
        entries_examined = 0
        symlink_count = 0
        special_file_count = 0
        traversed_home_count = 0
        
        # Maximum entries to examine per home directory to prevent runaway traversal
        MAX_ENTRIES_PER_HOME = 10000
        # Maximum depth to traverse
        MAX_DEPTH = 5
        
        for home_path in home_dirs:
            path = Path(home_path)
            if path.exists() and path.is_dir():
                existing_homes.append(home_path)
                traversed_home_count += 1
                
                # Count files and directories with bounded traversal
                # NEVER follows symlinks, uses lstat
                try:
                    file_count = 0
                    dir_count = 0
                    dir_size = 0
                    home_entries = 0
                    truncated = False
                    
                    for root, dirs, files in os.walk(path, followlinks=False, topdown=True):
                        # Check depth limit
                        try:
                            current_depth = len(Path(root).parts) - len(path.parts)
                        except (ValueError, TypeError):
                            current_depth = 0
                        
                        if current_depth > MAX_DEPTH:
                            dirs.clear()
                            continue
                        
                        # Filter out symlinked directories to prevent following them
                        dirs_to_remove = []
                        for d in dirs:
                            dir_path = Path(root) / d
                            if dir_path.is_symlink():
                                dirs_to_remove.append(d)
                                symlink_count += 1
                        for d in dirs_to_remove:
                            dirs.remove(d)
                        
                        dir_count += len(dirs)
                        
                        for f in files:
                            if home_entries >= MAX_ENTRIES_PER_HOME:
                                truncated = True
                                dirs.clear()
                                break
                            
                            home_entries += 1
                            entries_examined += 1
                            
                            try:
                                fp = Path(root) / f
                                # Use lstat to NOT follow symlinks
                                stat_info = fp.lstat()
                                
                                # Check if this is a symlink
                                if fp.is_symlink():
                                    symlink_count += 1
                                    continue  # Don't count symlink targets
                                
                                # Check for special files (not regular files)
                                import stat
                                mode = stat_info.st_mode
                                if not stat.S_ISREG(mode):
                                    # This is a special file (device, socket, FIFO, etc.)
                                    special_file_count += 1
                                    # Still count it as a file but don't add its size
                                    file_count += 1
                                    
                                    # Track mtime even for special files
                                    mtime = stat_info.st_mtime
                                    if oldest_mtime is None or mtime < oldest_mtime:
                                        oldest_mtime = mtime
                                    if newest_mtime is None or mtime > newest_mtime:
                                        newest_mtime = mtime
                                    continue
                                
                                # Regular file - count size
                                file_count += 1
                                # Use st_size (apparent size), not st_blocks * 512 (allocated)
                                dir_size += stat_info.st_size
                                mtime = stat_info.st_mtime
                                
                                if oldest_mtime is None or mtime < oldest_mtime:
                                    oldest_mtime = mtime
                                if newest_mtime is None or mtime > newest_mtime:
                                    newest_mtime = mtime
                            except PermissionError:
                                permission_denied_count += 1
                                continue
                            except (OSError, FileNotFoundError):
                                continue
                        
                        if truncated:
                            break
                    
                    total_files += file_count
                    total_dirs += dir_count
                    total_size_bytes += dir_size
                    
                    # Record truncation info if any home was truncated
                    if truncated:
                        if "truncation_info" not in result:
                            result["truncation_info"] = {}
                        result["truncation_info"]["home_truncated"] = True
                        result["truncation_info"]["reason"] = f"max_entries_per_home ({MAX_ENTRIES_PER_HOME}) reached"
                    
                except PermissionError:
                    permission_denied_count += 1
                except (OSError, FileNotFoundError):
                    pass
            else:
                missing_homes += 1
        
        home_stats: dict[str, Any] = {
            "total_home_dirs": len(home_dirs),
            "existing_home_count": len(existing_homes),
            "missing_home_count": missing_homes,
            "aggregate_file_count": total_files,
            "aggregate_dir_count": total_dirs,
            "aggregate_size_bytes": total_size_bytes,
            "oldest_file_mtime": oldest_mtime,
            "newest_file_mtime": newest_mtime,
            "entries_examined": entries_examined,
            "permission_denied_count": permission_denied_count,
            "symlink_count": symlink_count,
            "special_file_count": special_file_count,
            "traversed_home_count": traversed_home_count,
        }
        
        # Add truncation info if present
        if "truncation_info" in result:
            home_stats["truncation_info"] = result.pop("truncation_info")
        
        result["home_directory_statistics"] = home_stats
        
    except Exception as e:
        result["errors"].append(f"account_statistics: {str(e)}")
    
    # Login history metadata
    try:
        result["login_history_metadata"] = _get_login_history_stats()
    except Exception as e:
        result["errors"].append(f"login_history: {str(e)}")
    
    return result
