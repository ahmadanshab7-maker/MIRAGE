"""Filesystem statistics collector.

Collects aggregate filesystem statistics useful for research.
Does NOT collect file contents or sensitive data.

Collection Policy:
- Fixed set of directories to scan
- Never follows symlinks
- Avoids pseudo-filesystems (/proc, /sys, /dev, /run)
- Maximum depth limit (configurable, default 5)
- Maximum entries examined (configurable, default 10000)
- Reports truncation if limits are reached
- Reports permission-denied/error counts
"""

import os
import time
from pathlib import Path
from typing import Any, Optional

# Maximum number of filesystem entries to examine per path
MAX_ENTRIES_PER_PATH = 10000

# Maximum directory depth to traverse
MAX_DEPTH = 5

# Common directories to scan (read-only, non-sensitive)
SCAN_PATHS = [
    "/etc",
    "/usr/bin",
    "/usr/lib",
    "/var/log",
    "/tmp",
    "/home",
    "/opt",
    "/srv",
]

# Directories to explicitly avoid (pseudo-filesystems, sensitive areas)
EXCLUDE_PREFIXES = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/mnt",
    "/media",
}

# File type categories by extension
TEXT_EXTENSIONS = {".txt", ".md", ".rst", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".xml", ".html", ".css"}
SCRIPT_EXTENSIONS = {".sh", ".py", ".pl", ".rb", ".js", ".php"}
BINARY_EXTENSIONS = {".so", ".a", ".o", ".bin", ".exe", ".dll"}
ARCHIVE_EXTENSIONS = {".tar", ".gz", ".bz2", ".xz", ".zip", ".rar", ".7z"}
LOG_EXTENSIONS = {".log"}


def _categorize_extension(ext: str) -> Optional[str]:
    """Categorize a file by its extension."""
    ext_lower = ext.lower()
    if ext_lower in TEXT_EXTENSIONS:
        return "text"
    elif ext_lower in SCRIPT_EXTENSIONS:
        return "script"
    elif ext_lower in BINARY_EXTENSIONS:
        return "binary"
    elif ext_lower in ARCHIVE_EXTENSIONS:
        return "archive"
    elif ext_lower in LOG_EXTENSIONS:
        return "log"
    elif not ext:
        return "no_extension"
    else:
        return "other"


def _get_age_distribution(mtimes: list[float]) -> dict[str, Any]:
    """Calculate age distribution from modification times."""
    if not mtimes:
        return {
            "count": 0,
            "min_age_days": None,
            "max_age_days": None,
            "median_age_days": None,
            "mean_age_days": None,
            "by_period": {
                "last_day": 0,
                "last_week": 0,
                "last_month": 0,
                "last_year": 0,
                "older": 0,
            },
        }
    
    now = time.time()
    ages_days = [(now - mt) / 86400 for mt in mtimes]  # Convert seconds to days
    
    ages_sorted = sorted(ages_days)
    count = len(ages_sorted)
    
    # Calculate periods
    last_day = sum(1 for age in ages_days if age <= 1)
    last_week = sum(1 for age in ages_days if age <= 7)
    last_month = sum(1 for age in ages_days if age <= 30)
    last_year = sum(1 for age in ages_days if age <= 365)
    older = count - last_year
    
    # Median
    mid = count // 2
    if count % 2 == 0:
        median = (ages_sorted[mid - 1] + ages_sorted[mid]) / 2
    else:
        median = ages_sorted[mid]
    
    return {
        "count": count,
        "min_age_days": round(min(ages_days), 2),
        "max_age_days": round(max(ages_days), 2),
        "median_age_days": round(median, 2),
        "mean_age_days": round(sum(ages_days) / count, 2),
        "by_period": {
            "last_day": last_day,
            "last_week": last_week,
            "last_month": last_month,
            "last_year": last_year,
            "older": older,
        },
    }


def _scan_path(path_str: str) -> dict[str, Any]:
    """Scan a single path for filesystem statistics.
    
    Bounded traversal with explicit limits and error reporting.
    Never follows symlinks. Avoids pseudo-filesystems.
    Reports truncation if limits are reached.
    """
    result: dict[str, Any] = {
        "path": path_str,
        "exists": False,
        "is_readable": False,
        "file_count": 0,
        "directory_count": 0,
        "symlink_count": 0,
        "total_size_bytes": 0,
        "extension_counts": {},
        "type_counts": {
            "text": 0,
            "script": 0,
            "binary": 0,
            "archive": 0,
            "log": 0,
            "no_extension": 0,
            "other": 0,
        },
        "mtimes": [],  # Will be used for age distribution
        "entries_examined": 0,
        "truncated": False,
        "truncation_reason": None,
        "permission_denied_count": 0,
        "errors": [],
    }
    
    path = Path(path_str)
    
    # Check if path should be excluded
    path_str_resolved = str(path.resolve()) if path.exists() else path_str
    for exclude_prefix in EXCLUDE_PREFIXES:
        if path_str_resolved.startswith(exclude_prefix):
            result["errors"].append(f"path excluded (pseudo-filesystem): {exclude_prefix}")
            return result
    
    if not path.exists():
        result["errors"].append("path does not exist")
        return result
    
    result["exists"] = True
    
    try:
        if not os.access(path, os.R_OK):
            result["errors"].append("path not readable")
            return result
        result["is_readable"] = True
    except OSError:
        result["errors"].append("cannot check readability")
        return result
    
    entries_examined = 0
    permission_denied_count = 0
    
    try:
        for root, dirs, files in os.walk(path, followlinks=False):
            # Check depth limit
            root_depth = len(Path(root).parts)
            path_depth = len(path.parts)
            current_depth = root_depth - path_depth
            
            if current_depth > MAX_DEPTH:
                dirs.clear()
                continue
            
            # Count directories (excluding those we will skip)
            # Filter out pseudo-filesystem mount points
            dirs_to_remove = []
            for d in dirs:
                dir_path = Path(root) / d
                dir_path_str = str(dir_path.resolve()) if dir_path.exists() else str(dir_path)
                for exclude_prefix in EXCLUDE_PREFIXES:
                    if dir_path_str.startswith(exclude_prefix):
                        dirs_to_remove.append(d)
                        break
            for d in dirs_to_remove:
                dirs.remove(d)
            
            result["directory_count"] += len(dirs)
            
            for name in files:
                if entries_examined >= MAX_ENTRIES_PER_PATH:
                    result["truncated"] = True
                    result["truncation_reason"] = f"max_entries ({MAX_ENTRIES_PER_PATH}) reached"
                    dirs.clear()
                    break
                
                entries_examined += 1
                fp = Path(root) / name
                
                try:
                    stat_info = fp.lstat()  # Use lstat to not follow symlinks
                    
                    if os.path.islink(fp):
                        result["symlink_count"] += 1
                    else:
                        result["file_count"] += 1
                        result["total_size_bytes"] += stat_info.st_size
                        
                        # Extension analysis
                        ext = fp.suffix.lower()
                        result["extension_counts"][ext] = result["extension_counts"].get(ext, 0) + 1
                        
                        # Type categorization
                        category = _categorize_extension(ext)
                        if category:
                            result["type_counts"][category] = result["type_counts"].get(category, 0) + 1
                        
                        # Track mtime for age distribution
                        result["mtimes"].append(stat_info.st_mtime)
                        
                except PermissionError:
                    permission_denied_count += 1
                    continue
                except OSError:
                    continue
            
            if result["truncated"]:
                break
                
    except PermissionError as e:
        result["errors"].append(f"walk permission error: {str(e)}")
    except OSError as e:
        result["errors"].append(f"walk error: {str(e)}")
    
    result["entries_examined"] = entries_examined
    result["permission_denied_count"] = permission_denied_count
    
    # Calculate age distribution before returning
    age_dist = _get_age_distribution(result["mtimes"])
    result["age_distribution"] = age_dist
    
    # Remove raw mtimes from output (privacy)
    del result["mtimes"]
    
    return result


def collect() -> dict[str, Any]:
    """Collect filesystem statistics.
    
    Returns:
        Dictionary containing filesystem-level measurements.
        
    Notes:
        - Uses bounded traversal with explicit limits
        - Reports truncation and permission errors
        - Does not follow symlinks
        - Avoids pseudo-filesystems
    """
    result: dict[str, Any] = {
        "scanned_paths": [],
        "aggregate_statistics": {},
        "errors": [],
    }
    
    all_file_counts = []
    all_dir_counts = []
    all_size_bytes = 0
    all_mtimes: list[float] = []
    combined_extension_counts: dict[str, int] = {}
    combined_type_counts: dict[str, int] = {
        "text": 0,
        "script": 0,
        "binary": 0,
        "archive": 0,
        "log": 0,
        "no_extension": 0,
        "other": 0,
    }
    total_entries_examined = 0
    total_permission_denied = 0
    any_truncated = False
    truncation_reasons = []
    
    for scan_path in SCAN_PATHS:
        try:
            path_result = _scan_path(scan_path)
            result["scanned_paths"].append(path_result)
            
            if path_result["exists"] and path_result["is_readable"]:
                all_file_counts.append(path_result["file_count"])
                all_dir_counts.append(path_result["directory_count"])
                all_size_bytes += path_result["total_size_bytes"]
                total_entries_examined += path_result["entries_examined"]
                total_permission_denied += path_result["permission_denied_count"]
                
                if path_result["truncated"]:
                    any_truncated = True
                    truncation_reasons.append(f"{scan_path}: {path_result['truncation_reason']}")
                
                # Merge extension counts
                for ext, count in path_result["extension_counts"].items():
                    combined_extension_counts[ext] = combined_extension_counts.get(ext, 0) + count
                
                # Merge type counts
                for typ, count in path_result["type_counts"].items():
                    combined_type_counts[typ] = combined_type_counts.get(typ, 0) + count
                
                # Collect mtimes for global age distribution
                # Re-scan briefly to get mtimes (inefficient but keeps _scan_path clean)
                path = Path(scan_path)
                if path.exists():
                    try:
                        entries_for_agg = 0
                        for root, dirs, files in os.walk(path, followlinks=False):
                            # Apply same depth limit
                            root_depth = len(Path(root).parts)
                            path_depth = len(path.parts)
                            if root_depth - path_depth > MAX_DEPTH:
                                dirs.clear()
                                continue
                            
                            for name in files:
                                if entries_for_agg >= MAX_ENTRIES_PER_PATH:
                                    break
                                entries_for_agg += 1
                                fp = Path(root) / name
                                try:
                                    stat_info = fp.lstat()
                                    all_mtimes.append(stat_info.st_mtime)
                                except (OSError, PermissionError):
                                    continue
                    except (OSError, PermissionError):
                        pass
                        
        except Exception as e:
            result["errors"].append(f"{scan_path}: {str(e)}")
    
    # Aggregate statistics with completeness metadata
    aggregate_stats: dict[str, Any] = {
        "paths_scanned": len(result["scanned_paths"]),
        "paths_accessible": sum(1 for p in result["scanned_paths"] if p["is_readable"]),
        "total_files": sum(all_file_counts),
        "total_directories": sum(all_dir_counts),
        "total_size_bytes": all_size_bytes,
        "type_counts": combined_type_counts,
        "top_extensions": dict(sorted(combined_extension_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
        "age_distribution": _get_age_distribution(all_mtimes),
        "collection_complete": not any_truncated,
        "total_entries_examined": total_entries_examined,
        "total_permission_denied": total_permission_denied,
    }
    
    if any_truncated:
        aggregate_stats["truncation_reasons"] = truncation_reasons
    
    result["aggregate_statistics"] = aggregate_stats
    
    return result
