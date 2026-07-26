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


def _get_age_distribution(mtimes: list[float], reference_time: float) -> dict[str, Any]:
    """Calculate age distribution from modification times using mutually exclusive bins.
    
    Args:
        mtimes: List of modification timestamps
        reference_time: Single reference timestamp for the collector run
        
    Returns:
        Dictionary with count and mutually exclusive age bins.
        
    Notes:
        - Age bins are MUTUALLY EXCLUSIVE - each file belongs to exactly one bin
        - Bins: 0_to_1_day, 1_to_7_days, 7_to_30_days, 30_to_365_days, over_365_days, future_timestamp
        - Sum of all bins equals count
        - Future timestamps (mtime > reference_time) are counted separately
    """
    if not mtimes:
        return {
            "count": 0,
            "min_age_days": None,
            "max_age_days": None,
            "median_age_days": None,
            "mean_age_days": None,
            "by_period": {
                "0_to_1_day": 0,
                "1_to_7_days": 0,
                "7_to_30_days": 0,
                "30_to_365_days": 0,
                "over_365_days": 0,
                "future_timestamp": 0,
            },
        }
    
    # Calculate ages in days relative to reference time
    ages_days = [(reference_time - mt) / 86400 for mt in mtimes]  # Convert seconds to days
    
    ages_sorted = sorted(ages_days)
    count = len(ages_sorted)
    
    # Mutually exclusive bins
    # Files with negative age (mtime in future) go to future_timestamp
    future_timestamp = sum(1 for age in ages_days if age < 0)
    # 0 to 1 day (age >= 0 and age < 1)
    bin_0_to_1_day = sum(1 for age in ages_days if 0 <= age < 1)
    # 1 to 7 days (age >= 1 and age < 7)
    bin_1_to_7_days = sum(1 for age in ages_days if 1 <= age < 7)
    # 7 to 30 days (age >= 7 and age < 30)
    bin_7_to_30_days = sum(1 for age in ages_days if 7 <= age < 30)
    # 30 to 365 days (age >= 30 and age < 365)
    bin_30_to_365_days = sum(1 for age in ages_days if 30 <= age < 365)
    # Over 365 days (age >= 365)
    bin_over_365_days = sum(1 for age in ages_days if age >= 365)
    
    # Median calculation (only for non-future timestamps)
    non_future_ages = [age for age in ages_sorted if age >= 0]
    if non_future_ages:
        mid = len(non_future_ages) // 2
        if len(non_future_ages) % 2 == 0:
            median = (non_future_ages[mid - 1] + non_future_ages[mid]) / 2
        else:
            median = non_future_ages[mid]
    else:
        median = None
    
    # Mean calculation (only for non-future timestamps)
    mean_age = sum(a for a in ages_days if a >= 0) / len(non_future_ages) if non_future_ages else None
    
    # Min/max age (only considering non-future timestamps)
    min_age = min(non_future_ages) if non_future_ages else None
    max_age = max(non_future_ages) if non_future_ages else None
    
    return {
        "count": count,
        "min_age_days": round(min_age, 2) if min_age is not None else None,
        "max_age_days": round(max_age, 2) if max_age is not None else None,
        "median_age_days": round(median, 2) if median is not None else None,
        "mean_age_days": round(mean_age, 2) if mean_age is not None else None,
        "by_period": {
            "0_to_1_day": bin_0_to_1_day,
            "1_to_7_days": bin_1_to_7_days,
            "7_to_30_days": bin_7_to_30_days,
            "30_to_365_days": bin_30_to_365_days,
            "over_365_days": bin_over_365_days,
            "future_timestamp": future_timestamp,
        },
    }


def _scan_path(path_str: str, reference_time: float) -> dict[str, Any]:
    """Scan a single path for filesystem statistics.
    
    Bounded traversal with explicit limits and error reporting.
    Never follows symlinks. Avoids pseudo-filesystems.
    Reports truncation if limits are reached.
    
    Args:
        path_str: Path to scan
        reference_time: Single reference timestamp for age calculations
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
    
    # Calculate age distribution before returning using reference time
    age_dist = _get_age_distribution(result["mtimes"], reference_time)
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
        - Uses a single reference timestamp for all age calculations
    """
    result: dict[str, Any] = {
        "scanned_paths": [],
        "aggregate_statistics": {},
        "errors": [],
    }
    
    # Capture a single reference timestamp for this collector run
    # This ensures consistent age calculations across all files
    reference_time = time.time()
    
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
            path_result = _scan_path(scan_path, reference_time)
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
        "age_distribution": _get_age_distribution(all_mtimes, reference_time),
        "collection_complete": not any_truncated,
        "total_entries_examined": total_entries_examined,
        "total_permission_denied": total_permission_denied,
    }
    
    if any_truncated:
        aggregate_stats["truncation_reasons"] = truncation_reasons
    
    result["aggregate_statistics"] = aggregate_stats
    
    return result
