"""Tests for MIRAGE collectors and models.

These tests verify parsing/normalization logic where practical.
They do not validate the "correctness" of environmental measurements,
as those depend on the system being profiled.
"""

import json
import pytest
from datetime import datetime, timezone

from mirage.models.snapshot import Snapshot, SCHEMA_VERSION
from mirage.collectors import system, users, filesystem, software, runtime, network


class TestSnapshot:
    """Tests for the Snapshot model."""
    
    def test_snapshot_creation(self):
        """Test that a snapshot can be created with correct structure."""
        snapshot = Snapshot()
        data = snapshot.get_data()
        
        assert "schema_version" in data
        assert "metadata" in data
        assert "collectors" in data
        assert "errors" in data
        assert data["schema_version"] == SCHEMA_VERSION
    
    def test_snapshot_set_metadata(self):
        """Test metadata setting."""
        snapshot = Snapshot()
        snapshot.set_metadata(
            collector_name="test",
            collector_version="0.0.1",
            notes="Test notes",
        )
        
        metadata = snapshot.get_data()["metadata"]
        assert metadata["collector_name"] == "test"
        assert metadata["collector_version"] == "0.0.1"
        assert metadata["notes"] == "Test notes"
        assert "collected_at" in metadata
        # Hostname should NOT be present (privacy)
        assert "hostname" not in metadata
    
    def test_snapshot_timestamp_is_utc(self):
        """Test that the timestamp is in UTC."""
        snapshot = Snapshot()
        snapshot.set_metadata()
        
        timestamp_str = snapshot.get_data()["metadata"]["collected_at"]
        # Should parse without error and contain timezone info
        dt = datetime.fromisoformat(timestamp_str)
        assert dt.tzinfo is not None
    
    def test_snapshot_add_collector_result(self):
        """Test adding collector results."""
        snapshot = Snapshot()
        result = {"measurement": 42, "errors": []}
        
        snapshot.add_collector_result("test_collector", result)
        
        data = snapshot.get_data()
        assert "test_collector" in data["collectors"]
        assert data["collectors"]["test_collector"]["measurement"] == 42
    
    def test_snapshot_add_collector_result_with_errors(self):
        """Test that collector errors are propagated."""
        snapshot = Snapshot()
        result = {"measurement": 42, "errors": ["error1", "error2"]}
        
        snapshot.add_collector_result("test_collector", result)
        
        data = snapshot.get_data()
        assert len(data["errors"]) == 2
        assert "test_collector: error1" in data["errors"]
        assert "test_collector: error2" in data["errors"]
    
    def test_snapshot_to_json(self):
        """Test JSON serialization."""
        snapshot = Snapshot()
        snapshot.set_metadata(collector_name="test")
        snapshot.add_collector_result("sys", {"data": 1})
        
        json_str = snapshot.to_json()
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["schema_version"] == SCHEMA_VERSION
    
    def test_snapshot_from_json_roundtrip(self):
        """Test JSON roundtrip."""
        snapshot1 = Snapshot()
        snapshot1.set_metadata(collector_name="roundtrip_test")
        snapshot1.add_collector_result("test", {"value": 123})
        
        json_str = snapshot1.to_json()
        snapshot2 = Snapshot.from_json(json_str)
        
        data1 = snapshot1.get_data()
        data2 = snapshot2.get_data()
        
        assert data1["schema_version"] == data2["schema_version"]
        assert data1["metadata"]["collector_name"] == data2["metadata"]["collector_name"]
        assert data1["collectors"]["test"]["value"] == data2["collectors"]["test"]["value"]
    
    def test_snapshot_validate(self):
        """Test snapshot validation."""
        snapshot = Snapshot()
        snapshot.set_metadata()
        snapshot.add_collector_result("test", {})
        
        errors = snapshot.validate()
        assert len(errors) == 0
    
    def test_snapshot_validate_missing_metadata(self):
        """Test validation catches missing metadata."""
        snapshot = Snapshot()
        # Don't set metadata
        snapshot._data["metadata"] = {}
        
        errors = snapshot.validate()
        assert any("collected_at" in e for e in errors)
    
    def test_snapshot_repr(self):
        """Test string representation."""
        snapshot = Snapshot()
        snapshot.add_collector_result("test", {"errors": ["e1"]})
        
        repr_str = repr(snapshot)
        assert "Snapshot" in repr_str
        assert "collectors=1" in repr_str
        assert "errors=1" in repr_str


class TestSystemCollector:
    """Tests for the system collector parsing logic."""
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = system.collect()
        assert isinstance(result, dict)
    
    def test_collect_has_required_keys(self):
        """Test that required keys are present."""
        result = system.collect()
        
        # hostname intentionally excluded for privacy
        required_keys = ["os", "kernel", "architecture", 
                        "cpu", "memory", "storage", "uptime_seconds", 
                        "virtualization", "errors"]
        for key in required_keys:
            assert key in result
    
    def test_hostname_not_collected(self):
        """Test that hostname field is not present (privacy)."""
        result = system.collect()
        assert "hostname" not in result
    
    def test_virtualization_type_never_bare_metal(self):
        """Test that virtualization_type is never 'bare-metal'."""
        result = system._detect_virtualization()
        # Should be 'vm', 'container', or 'unknown' - never 'bare-metal'
        assert result["virtualization_type"] in ("vm", "container", "unknown")
    
    def test_cpu_parsing_has_expected_fields(self):
        """Test CPU parsing produces expected fields (no flags for privacy)."""
        cpu_info = system._parse_cpuinfo()
        
        assert "model_name" in cpu_info
        assert "cpu_cores" in cpu_info
        # flags intentionally excluded to prevent fingerprinting
        assert "flags" not in cpu_info
    
    def test_meminfo_parsing_has_expected_fields(self):
        """Test memory parsing produces expected fields."""
        mem_info = system._parse_meminfo()
        
        assert "total_kb" in mem_info
        assert "free_kb" in mem_info
        assert "available_kb" in mem_info


class TestUsersCollector:
    """Tests for the users collector."""
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = users.collect()
        assert isinstance(result, dict)
    
    def test_collect_has_required_keys(self):
        """Test that required keys are present."""
        result = users.collect()
        
        required_keys = ["account_statistics", "home_directory_statistics",
                        "login_history_metadata", "errors"]
        for key in required_keys:
            assert key in result
    
    def test_account_statistics_structure(self):
        """Test account statistics has expected structure."""
        result = users.collect()
        stats = result["account_statistics"]
        
        assert "total_count" in stats
        # uid_policy contains source information
        assert "uid_policy" in stats
        assert "source" in stats["uid_policy"]
    
    def test_uid_classification_requires_config(self):
        """Test that UID classification requires host configuration."""
        result = users.collect()
        stats = result["account_statistics"]
        
        # Check uid_policy structure
        assert "uid_policy" in stats
        policy = stats["uid_policy"]
        assert "source" in policy
        assert "uid_min" in policy
        assert "uid_max" in policy
        
        # If uid_policy source is None or 'unavailable', classification should be None
        if policy.get("source") in (None, "unavailable", "not_configured"):
            assert stats.get("system_account_count") is None
            assert stats.get("regular_account_count") is None
            assert "classification_unavailable_reason" in stats


class TestFilesystemCollector:
    """Tests for the filesystem collector parsing logic."""
    
    def test_age_distribution_empty(self):
        """Test age distribution with empty input."""
        result = filesystem._get_age_distribution([])
        
        assert result["count"] == 0
        assert result["min_age_days"] is None
        assert result["by_period"]["last_day"] == 0
    
    def test_age_distribution_single_value(self):
        """Test age distribution with single value."""
        import time
        now = time.time()
        result = filesystem._get_age_distribution([now])
        
        assert result["count"] == 1
        assert result["min_age_days"] == result["max_age_days"]
    
    def test_age_distribution_periods(self):
        """Test age distribution period counting."""
        import time
        now = time.time()
        day = 86400  # seconds
        
        mtimes = [
            now - day * 0.5,    # 12 hours ago
            now - day * 3,      # 3 days ago
            now - day * 15,     # 15 days ago
            now - day * 400,    # 400 days ago
        ]
        
        result = filesystem._get_age_distribution(mtimes)
        
        assert result["by_period"]["last_day"] == 1
        assert result["by_period"]["last_week"] == 2
        assert result["by_period"]["last_month"] == 3
        assert result["by_period"]["last_year"] == 3
        assert result["by_period"]["older"] == 1
    
    def test_categorize_extension(self):
        """Test file extension categorization."""
        assert filesystem._categorize_extension(".txt") == "text"
        assert filesystem._categorize_extension(".py") == "script"
        assert filesystem._categorize_extension(".so") == "binary"
        # .gz is in ARCHIVE_EXTENSIONS
        assert filesystem._categorize_extension(".gz") == "archive"
        assert filesystem._categorize_extension(".zip") == "archive"
        assert filesystem._categorize_extension(".log") == "log"
        assert filesystem._categorize_extension("") == "no_extension"
        assert filesystem._categorize_extension(".xyz") == "other"
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = filesystem.collect()
        assert isinstance(result, dict)
    
    def test_filesystem_reports_truncation_metadata(self):
        """Test that filesystem collection reports truncation status."""
        result = filesystem.collect()
        agg = result["aggregate_statistics"]
        
        assert "collection_complete" in agg
        assert "total_entries_examined" in agg
        assert "total_permission_denied" in agg
    
    def test_scan_path_has_bounded_fields(self):
        """Test that individual path scans report bounded traversal info."""
        # Test with /etc which should exist and be readable
        result = filesystem._scan_path("/etc")
        
        assert "entries_examined" in result
        assert "truncated" in result
        assert "permission_denied_count" in result


class TestSoftwareCollector:
    """Tests for the software collector."""
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = software.collect()
        assert isinstance(result, dict)
    
    def test_collect_has_required_keys(self):
        """Test that required keys are present."""
        result = software.collect()
        
        required_keys = ["primary_package_manager", "package_managers",
                        "additional_software", "errors"]
        for key in required_keys:
            assert key in result


class TestRuntimeCollector:
    """Tests for the runtime collector."""
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = runtime.collect()
        assert isinstance(result, dict)
    
    def test_collect_has_required_keys(self):
        """Test that required keys are present."""
        result = runtime.collect()
        
        required_keys = ["process_statistics", "service_statistics",
                        "init_system", "errors"]
        for key in required_keys:
            assert key in result
    
    def test_process_stats_structure(self):
        """Test process statistics structure."""
        result = runtime.collect()
        stats = result["process_statistics"]
        
        assert "total_processes" in stats
        assert "unique_comms" in stats
        assert "by_state" in stats
        assert "zombie_count" in stats


class TestNetworkCollector:
    """Tests for the network collector parsing logic."""
    
    def test_collect_returns_dict(self):
        """Test that collect returns a dictionary."""
        result = network.collect()
        assert isinstance(result, dict)
    
    def test_collect_has_required_keys(self):
        """Test that required keys are present."""
        result = network.collect()
        
        required_keys = ["interfaces", "routing", "dns", 
                        "arp_statistics", "network_management", "errors"]
        for key in required_keys:
            assert key in result
    
    def test_no_mac_addresses_collected(self):
        """Test that raw MAC addresses are not collected."""
        result = network.collect()
        for iface, data in result["interfaces"].items():
            assert "mac_address" not in data
            # Should have has_hardware_address boolean instead
            assert "has_hardware_address" in data or "operstate" in data
    
    def test_no_dns_addresses_collected(self):
        """Test that DNS nameserver addresses are not collected."""
        result = network._parse_dns_config()
        assert "nameservers" not in result
        assert "search_domains" not in result
        # Should have counts instead
        assert "nameserver_count" in result
        assert "search_domain_count" in result
    
    def test_no_route_ips_collected(self):
        """Test that routing table IP addresses are not collected."""
        result = network._parse_routing_table()
        assert "routes" not in result
        # Should have counts instead
        assert "route_count" in result
        assert "default_gateway_count" in result
    
    def test_dns_config_structure(self):
        """Test DNS config structure."""
        result = network._parse_dns_config()
        
        assert "nameserver_count" in result
        assert "search_domain_count" in result
        assert "options_count" in result
        assert "resolv_conf_exists" in result


class TestIntegration:
    """Integration tests for the full collection pipeline."""
    
    def test_full_snapshot_creation(self):
        """Test creating a complete snapshot with all collectors."""
        snapshot = Snapshot()
        snapshot.set_metadata(collector_name="integration_test")
        
        collectors = [
            ("system", system.collect),
            ("users", users.collect),
            ("filesystem", filesystem.collect),
            ("software", software.collect),
            ("runtime", runtime.collect),
            ("network", network.collect),
        ]
        
        for name, collect_fn in collectors:
            result = collect_fn()
            snapshot.add_collector_result(name, result)
        
        # Validate the snapshot
        errors = snapshot.validate()
        assert len(errors) == 0, f"Validation errors: {errors}"
        
        # Check JSON serialization
        json_str = snapshot.to_json()
        data = json.loads(json_str)
        
        assert data["schema_version"] == SCHEMA_VERSION
        assert len(data["collectors"]) == 6
    
    def test_selective_collection(self):
        """Test collecting only specific collectors."""
        snapshot = Snapshot()
        snapshot.set_metadata()
        
        # Only collect system and network
        snapshot.add_collector_result("system", system.collect())
        snapshot.add_collector_result("network", network.collect())
        
        data = snapshot.get_data()
        assert len(data["collectors"]) == 2
        assert "system" in data["collectors"]
        assert "network" in data["collectors"]
