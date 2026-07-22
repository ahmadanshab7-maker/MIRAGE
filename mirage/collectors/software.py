"""Software and package information collector.

Collects statistics about installed packages and package managers.
Does not collect sensitive configuration or credentials.
"""

import os
import re
from pathlib import Path
from typing import Any, Optional
import subprocess


def _read_file(path: str) -> Optional[str]:
    """Safely read a file, returning None if unavailable."""
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def _run_command_safely(args: list[str], timeout: float = 5.0) -> Optional[str]:
    """Run a command safely without shell=True, returning stdout or None."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return None


def _parse_dpkg_status() -> dict[str, Any]:
    """Parse /var/lib/dpkg/status for Debian-based systems."""
    result: dict[str, Any] = {
        "package_manager": "dpkg",
        "total_packages": 0,
        "installed_count": 0,
        "half_installed_count": 0,
        "config_files_count": 0,
        "unpacked_count": 0,
        "failed_config_count": 0,
        "failed_install_count": 0,
        "essential_count": 0,
        "by_priority": {},
        "by_section": {},
    }
    
    content = _read_file("/var/lib/dpkg/status")
    if not content:
        result["package_manager"] = None
        return result
    
    current_pkg: dict[str, str] = {}
    
    for line in content.splitlines():
        if not line.strip():
            # End of package entry
            if current_pkg.get("package"):
                result["total_packages"] += 1
                
                status = current_pkg.get("status", "")
                if "install ok installed" in status:
                    result["installed_count"] += 1
                elif "half-installed" in status:
                    result["half_installed_count"] += 1
                elif "config-files" in status:
                    result["config_files_count"] += 1
                elif "unpacked" in status:
                    result["unpacked_count"] += 1
                elif "failed-config" in status:
                    result["failed_config_count"] += 1
                elif "failed-install" in status:
                    result["failed_install_count"] += 1
                
                if current_pkg.get("essential") == "yes":
                    result["essential_count"] += 1
                
                priority = current_pkg.get("priority", "unknown")
                result["by_priority"][priority] = result["by_priority"].get(priority, 0) + 1
                
                section = current_pkg.get("section", "unknown")
                # Section may have subcategory like "libs/libdevel"
                main_section = section.split("/")[0] if section else "unknown"
                result["by_section"][main_section] = result["by_section"].get(main_section, 0) + 1
            
            current_pkg = {}
        elif ":" in line:
            key, value = line.split(":", 1)
            current_pkg[key.strip().lower()] = value.strip()
    
    return result


def _parse_rpm_database() -> dict[str, Any]:
    """Query RPM database for RPM-based systems."""
    result: dict[str, Any] = {
        "package_manager": "rpm",
        "total_packages": 0,
        "errors": [],
    }
    
    # Try rpm command first
    output = _run_command_safely(["rpm", "-qa", "--qf", "%{NAME}\n"], timeout=10.0)
    if output:
        packages = [p for p in output.splitlines() if p.strip()]
        result["total_packages"] = len(packages)
        return result
    
    # Fallback to reading rpm database files directly (less reliable)
    rpm_db = Path("/var/lib/rpm/Packages")
    if rpm_db.exists():
        result["note"] = "RPM database exists but rpm command unavailable"
    
    return result


def _check_pacman() -> dict[str, Any]:
    """Check pacman package manager for Arch-based systems."""
    result: dict[str, Any] = {
        "package_manager": "pacman",
        "total_packages": 0,
        "explicit_count": 0,
        "dependency_count": 0,
    }
    
    output = _run_command_safely(["pacman", "-Q", "-q"], timeout=10.0)
    if output:
        packages = [p for p in output.splitlines() if p.strip()]
        result["total_packages"] = len(packages)
        
        # Count explicitly installed vs dependencies
        explicit_output = _run_command_safely(["pacman", "-Q", "-e", "-q"], timeout=10.0)
        if explicit_output:
            result["explicit_count"] = len([p for p in explicit_output.splitlines() if p.strip()])
            result["dependency_count"] = result["total_packages"] - result["explicit_count"]
    
    return result


def _check_flatpak() -> dict[str, Any]:
    """Check Flatpak installations."""
    result: dict[str, Any] = {
        "flatpak_available": False,
        "system_packages": 0,
        "user_packages": 0,
    }
    
    output = _run_command_safely(["flatpak", "list", "--app", "-q"], timeout=10.0)
    if output is not None:
        result["flatpak_available"] = True
        lines = [l for l in output.splitlines() if l.strip()]
        # Rough estimate: count system vs user would need more parsing
        result["system_packages"] = len(lines)  # Simplified
    
    return result


def _check_snap() -> dict[str, Any]:
    """Check Snap installations."""
    result: dict[str, Any] = {
        "snap_available": False,
        "installed_count": 0,
    }
    
    output = _run_command_safely(["snap", "list"], timeout=10.0)
    if output is not None:
        result["snap_available"] = True
        lines = [l for l in output.splitlines() if l.strip()]
        # First line is header
        result["installed_count"] = max(0, len(lines) - 1)
    
    return result


def _check_appimage_locations() -> dict[str, Any]:
    """Check common AppImage locations."""
    result: dict[str, Any] = {
        "appimage_locations": [],
        "total_found": 0,
    }
    
    locations = [
        "/home",
        "/opt",
        "/usr/local/bin",
        os.path.expanduser("~/Applications"),
    ]
    
    for loc in locations:
        path = Path(loc)
        if path.exists():
            try:
                appimages = list(path.rglob("*.AppImage")) + list(path.rglob("*.appimage"))
                if appimages:
                    result["appimage_locations"].append({
                        "path": loc,
                        "count": len(appimages),
                    })
                    result["total_found"] += len(appimages)
            except (OSError, PermissionError):
                continue
    
    return result


def collect() -> dict[str, Any]:
    """Collect software and package information.
    
    Returns:
        Dictionary containing software-level measurements.
    """
    result: dict[str, Any] = {
        "primary_package_manager": None,
        "package_managers": {},
        "additional_software": {},
        "errors": [],
    }
    
    # Detect and query primary package manager
    dpkg_result = None
    rpm_result = None
    pacman_result = None
    
    # Check for dpkg (Debian/Ubuntu)
    if Path("/var/lib/dpkg/status").exists():
        try:
            dpkg_result = _parse_dpkg_status()
            result["primary_package_manager"] = "dpkg"
        except Exception as e:
            result["errors"].append(f"dpkg: {str(e)}")
    
    # Check for RPM (RHEL/Fedora/CentOS)
    if Path("/var/lib/rpm").exists() or _run_command_safely(["which", "rpm"]):
        try:
            rpm_result = _parse_rpm_database()
            if not result["primary_package_manager"]:
                result["primary_package_manager"] = "rpm"
        except Exception as e:
            result["errors"].append(f"rpm: {str(e)}")
    
    # Check for pacman (Arch)
    pacman_path = Path("/usr/bin/pacman")
    if pacman_path.exists():
        try:
            pacman_result = _check_pacman()
            if not result["primary_package_manager"]:
                result["primary_package_manager"] = "pacman"
        except Exception as e:
            result["errors"].append(f"pacman: {str(e)}")
    
    # Store results
    if dpkg_result:
        result["package_managers"]["dpkg"] = dpkg_result
    if rpm_result:
        result["package_managers"]["rpm"] = rpm_result
    if pacman_result and pacman_result.get("total_packages", 0) > 0:
        result["package_managers"]["pacman"] = pacman_result
    
    # Additional software sources
    try:
        result["additional_software"]["flatpak"] = _check_flatpak()
    except Exception as e:
        result["errors"].append(f"flatpak: {str(e)}")
    
    try:
        result["additional_software"]["snap"] = _check_snap()
    except Exception as e:
        result["errors"].append(f"snap: {str(e)}")
    
    try:
        result["additional_software"]["appimage"] = _check_appimage_locations()
    except Exception as e:
        result["errors"].append(f"appimage: {str(e)}")
    
    return result
