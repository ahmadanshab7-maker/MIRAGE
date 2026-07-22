"""Network configuration collector.

Collects interface statistics, routing configuration metadata, and DNS configuration.
Does NOT scan the network or contact external systems.
Does NOT collect hardware addresses, IP addresses, or DNS server addresses.
"""

import os
import re
from pathlib import Path
from typing import Any, Optional


def _read_proc_file(path: str) -> Optional[str]:
    """Safely read a /proc or /sys file, returning None if unavailable."""
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError, FileNotFoundError):
        return None


def _parse_netdev() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev for interface statistics."""
    result: dict[str, dict[str, int]] = {}
    
    content = _read_proc_file("/proc/net/dev")
    if not content:
        return result
    
    # Skip header lines
    lines = content.splitlines()[2:]
    
    for line in lines:
        # Format: iface: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame rx_compressed rx_multicast tx_bytes ...
        match = re.match(r"\s*(\w+):\s+(.+)", line)
        if not match:
            continue
        
        iface = match.group(1)
        values = match.group(2).split()
        
        if len(values) >= 10:
            result[iface] = {
                "rx_bytes": int(values[0]),
                "rx_packets": int(values[1]),
                "rx_errors": int(values[2]),
                "rx_dropped": int(values[3]),
                "tx_bytes": int(values[8]),
                "tx_packets": int(values[9]),
                "tx_errors": int(values[10]),
                "tx_dropped": int(values[11]),
            }
    
    return result


def _get_interface_addresses() -> dict[str, list[dict[str, Any]]]:
    """Get interface metadata without hardware identifiers.
    
    Returns interface count and state information only.
    Does NOT collect MAC addresses (privacy/fingerprinting concern).
    """
    result: dict[str, list[dict[str, Any]]] = {}
    
    try:
        # Get all network interfaces
        interfaces = os.listdir("/sys/class/net")
    except (OSError, PermissionError):
        interfaces = []
    
    for iface in interfaces:
        # Check operstate
        state_path = Path(f"/sys/class/net/{iface}/operstate")
        operstate = None
        if state_path.exists():
            try:
                operstate = state_path.read_text().strip()
            except (OSError, PermissionError):
                pass
        
        # Get MTU
        mtu_path = Path(f"/sys/class/net/{iface}/mtu")
        mtu = None
        if mtu_path.exists():
            try:
                mtu = int(mtu_path.read_text().strip())
            except (OSError, ValueError, PermissionError):
                pass
        
        # Get link speed if available
        speed_path = Path(f"/sys/class/net/{iface}/speed")
        speed = None
        if speed_path.exists():
            try:
                speed_str = speed_path.read_text().strip()
                if speed_str.isdigit():
                    speed = int(speed_str)
            except (OSError, ValueError, PermissionError):
                pass
        
        # Check if interface has a hardware address (without collecting it)
        addr_path = Path(f"/sys/class/net/{iface}/address")
        has_mac = False
        if addr_path.exists():
            try:
                mac = addr_path.read_text().strip()
                # Only record that a MAC exists, not the actual value
                has_mac = mac and mac != "00:00:00:00:00:00"
            except (OSError, PermissionError):
                pass
        
        result[iface] = {
            "has_hardware_address": has_mac,  # Boolean only, no actual MAC
            "operstate": operstate,
            "mtu": mtu,
            "speed_mbps": speed,
        }
    
    return result


def _parse_routing_table() -> dict[str, Any]:
    """Parse /proc/net/route for routing table metadata only.
    
    Does NOT collect actual gateway or destination IP addresses
    (privacy/organizational fingerprinting concern).
    Only collects counts and interface information.
    """
    result: dict[str, Any] = {
        "route_count": 0,
        "default_gateway_count": 0,
        "interfaces_with_routes": [],
    }
    
    content = _read_proc_file("/proc/net/route")
    if not content:
        return result
    
    lines = content.splitlines()[1:]  # Skip header
    interfaces_seen: set[str] = set()
    
    for line in lines:
        parts = line.split()
        if len(parts) >= 8:
            iface = parts[0]
            destination = parts[1]
            gateway = parts[2]
            
            interfaces_seen.add(iface)
            result["route_count"] += 1
            
            # Count default routes (0.0.0.0 destination encoded as hex)
            if destination == "00000000":
                result["default_gateway_count"] += 1
    
    result["interfaces_with_routes"] = sorted(list(interfaces_seen))
    
    return result


def _parse_dns_config() -> dict[str, Any]:
    """Parse /etc/resolv.conf for DNS configuration metadata only.
    
    Does NOT collect actual nameserver addresses or search domains
    (privacy/organizational fingerprinting concern).
    Only collects counts and configuration presence.
    """
    result: dict[str, Any] = {
        "nameserver_count": 0,
        "search_domain_count": 0,
        "options_count": 0,
        "resolv_conf_exists": False,
    }
    
    resolv_path = Path("/etc/resolv.conf")
    if not resolv_path.exists():
        return result
    
    result["resolv_conf_exists"] = True
    
    try:
        content = resolv_path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                directive = parts[0].lower()
                
                if directive == "nameserver":
                    result["nameserver_count"] += 1
                elif directive == "search":
                    result["search_domain_count"] += len(parts[1:])
                elif directive == "options":
                    result["options_count"] += len(parts[1:])
    except (OSError, PermissionError):
        pass
    
    return result


def _get_arp_cache() -> dict[str, Any]:
    """Get ARP cache statistics (not individual entries for privacy)."""
    result: dict[str, Any] = {
        "arp_entry_count": 0,
        "arp_table_exists": False,
    }
    
    arp_path = Path("/proc/net/arp")
    if not arp_path.exists():
        return result
    
    result["arp_table_exists"] = True
    
    try:
        content = arp_path.read_text()
        lines = content.splitlines()[1:]  # Skip header
        result["arp_entry_count"] = len([l for l in lines if l.strip()])
    except (OSError, PermissionError):
        pass
    
    return result


def _check_network_manager() -> dict[str, Any]:
    """Check for NetworkManager or other network management tools."""
    result: dict[str, Any] = {
        "network_manager_available": False,
        "systemd_networkd_available": False,
        "interfaces_managed": None,
    }
    
    # Check for NetworkManager
    nm_socket = Path("/run/NetworkManager/NetworkManager")
    if nm_socket.exists() or Path("/usr/bin/nmcli").exists():
        result["network_manager_available"] = True
    
    # Check for systemd-networkd
    systemd_networkd = Path("/run/systemd/netif")
    if systemd_networkd.exists():
        result["systemd_networkd_available"] = True
    
    return result


def collect() -> dict[str, Any]:
    """Collect network configuration information.
    
    Returns:
        Dictionary containing network-level measurements.
    """
    result: dict[str, Any] = {
        "interfaces": {},
        "routing": {},
        "dns": {},
        "arp_statistics": {},
        "network_management": {},
        "errors": [],
    }
    
    # Interface statistics
    try:
        netdev_stats = _parse_netdev()
        iface_addrs = _get_interface_addresses()
        
        # Merge stats and addresses
        for iface, addrs in iface_addrs.items():
            result["interfaces"][iface] = {
                **addrs,
                "statistics": netdev_stats.get(iface, {}),
            }
        
        # Add interfaces that only appear in netdev
        for iface, stats in netdev_stats.items():
            if iface not in result["interfaces"]:
                result["interfaces"][iface] = {
                    "statistics": stats,
                }
    except Exception as e:
        result["errors"].append(f"interfaces: {str(e)}")
    
    # Routing table
    try:
        result["routing"] = _parse_routing_table()
    except Exception as e:
        result["errors"].append(f"routing: {str(e)}")
    
    # DNS configuration
    try:
        result["dns"] = _parse_dns_config()
    except Exception as e:
        result["errors"].append(f"dns: {str(e)}")
    
    # ARP statistics
    try:
        result["arp_statistics"] = _get_arp_cache()
    except Exception as e:
        result["errors"].append(f"arp: {str(e)}")
    
    # Network management
    try:
        result["network_management"] = _check_network_manager()
    except Exception as e:
        result["errors"].append(f"network_management: {str(e)}")
    
    return result
