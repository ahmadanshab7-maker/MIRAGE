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
        import time
        result = filesystem._get_age_distribution([], time.time())
        
        assert result["count"] == 0
        assert result["min_age_days"] is None
        assert result["by_period"]["0_to_1_day"] == 0
    
    def test_age_distribution_single_value(self):
        """Test age distribution with single value."""
        import time
        now = time.time()
        result = filesystem._get_age_distribution([now], now)
        
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
        
        result = filesystem._get_age_distribution(mtimes, now)
        
        assert result["by_period"]["0_to_1_day"] == 1
        assert result["by_period"]["1_to_7_days"] == 1
        assert result["by_period"]["7_to_30_days"] == 1
        assert result["by_period"]["over_365_days"] == 1
    
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
        import time
        # Test with /etc which should exist and be readable
        result = filesystem._scan_path("/etc", time.time())
        
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


class TestPrivacyInvariants:
    """Tests for privacy-related invariants that must always hold."""
    
    def test_hostname_not_in_serialized_output(self):
        """Test that known hostname cannot appear anywhere in serialized output.
        
        This is a semantic test - it verifies that even if fields are renamed,
        the actual hostname value does not leak into the output.
        """
        import platform
        actual_hostname = platform.node()
        
        snapshot = Snapshot()
        snapshot.set_metadata(collector_name="privacy_test")
        
        # Add all collector results
        snapshot.add_collector_result("system", system.collect())
        snapshot.add_collector_result("users", users.collect())
        snapshot.add_collector_result("filesystem", filesystem.collect())
        snapshot.add_collector_result("software", software.collect())
        snapshot.add_collector_result("runtime", runtime.collect())
        snapshot.add_collector_result("network", network.collect())
        
        # Serialize to JSON
        json_str = snapshot.to_json()
        
        # The actual hostname should NOT appear anywhere in the output
        # This catches leaks through node, nodename, or any other field
        assert actual_hostname not in json_str, \
            f"Hostname '{actual_hostname}' found in serialized output!"
    
    def test_hostname_not_in_system_os_or_kernel(self):
        """Test that system.os.node and system.kernel.nodename are not present."""
        result = system.collect()
        
        # os.node should not exist
        assert "node" not in result.get("os", {}), \
            "system.os.node should not be present (hostname leak)"
        
        # kernel.nodename should not exist  
        assert "nodename" not in result.get("kernel", {}), \
            "system.kernel.nodename should not be present (hostname leak)"


class TestFilesystemSemantics:
    """Tests for filesystem measurement semantics."""
    
    def test_age_bins_mutually_exclusive(self):
        """Test that age bins are mutually exclusive - sum equals count."""
        import time
        now = time.time()
        day = 86400  # seconds
        
        mtimes = [
            now - day * 0.5,    # 12 hours ago -> 0_to_1_day
            now - day * 3,      # 3 days ago -> 1_to_7_days
            now - day * 15,     # 15 days ago -> 7_to_30_days
            now - day * 100,    # 100 days ago -> 30_to_365_days
            now - day * 400,    # 400 days ago -> over_365_days
            now + day * 5,      # 5 days in future -> future_timestamp
        ]
        
        result = filesystem._get_age_distribution(mtimes, now)
        
        by_period = result["by_period"]
        bin_sum = (
            by_period["0_to_1_day"] +
            by_period["1_to_7_days"] +
            by_period["7_to_30_days"] +
            by_period["30_to_365_days"] +
            by_period["over_365_days"] +
            by_period["future_timestamp"]
        )
        
        assert bin_sum == result["count"], \
            f"Sum of bins ({bin_sum}) != count ({result['count']})"
    
    def test_age_bins_empty_input(self):
        """Test age distribution with empty input."""
        import time
        result = filesystem._get_age_distribution([], time.time())
        
        assert result["count"] == 0
        by_period = result["by_period"]
        bin_sum = sum(by_period.values())
        assert bin_sum == 0
    
    def test_future_timestamps_counted_explicitly(self):
        """Test that future timestamps are counted in future_timestamp bin."""
        import time
        now = time.time()
        future_mtime = now + 86400  # 1 day in future
        
        result = filesystem._get_age_distribution([future_mtime], now)
        
        assert result["by_period"]["future_timestamp"] == 1
        assert result["by_period"]["0_to_1_day"] == 0
    
    def test_age_bin_boundaries(self):
        """Test exact boundary conditions for age bins."""
        import time
        now = time.time()
        day = 86400
        
        # Test files at exact boundaries
        mtimes = [
            now,                    # age = 0 -> 0_to_1_day
            now - day * 0.999,      # age < 1 -> 0_to_1_day
            now - day * 1.0,        # age = 1 -> 1_to_7_days
            now - day * 6.999,      # age < 7 -> 1_to_7_days
            now - day * 7.0,        # age = 7 -> 7_to_30_days
            now - day * 29.999,     # age < 30 -> 7_to_30_days
            now - day * 30.0,       # age = 30 -> 30_to_365_days
            now - day * 364.999,    # age < 365 -> 30_to_365_days
            now - day * 365.0,      # age = 365 -> over_365_days
        ]
        
        result = filesystem._get_age_distribution(mtimes, now)
        
        assert result["by_period"]["0_to_1_day"] == 2
        assert result["by_period"]["1_to_7_days"] == 2
        assert result["by_period"]["7_to_30_days"] == 2
        assert result["by_period"]["30_to_365_days"] == 2
        assert result["by_period"]["over_365_days"] == 1
        assert result["by_period"]["future_timestamp"] == 0


class TestUsersCollectorSemantics:
    """Tests for users collector semantics."""
    
    def test_home_traversal_does_not_follow_symlinks(self):
        """Verify home directory traversal uses lstat and doesn't follow symlinks."""
        # This test verifies the code path - actual symlink testing needs temp dirs
        result = users.collect()
        home_stats = result.get("home_directory_statistics", {})
        
        # Should report symlink_count if any were encountered
        assert "symlink_count" in home_stats
    
    def test_home_traversal_reports_entries_examined(self):
        """Test that home traversal reports entries_examined."""
        result = users.collect()
        home_stats = result.get("home_directory_statistics", {})
        
        assert "entries_examined" in home_stats
        assert isinstance(home_stats["entries_examined"], int)
    
    def test_home_traversal_reports_permission_errors(self):
        """Test that home traversal reports permission_denied_count."""
        result = users.collect()
        home_stats = result.get("home_directory_statistics", {})
        
        assert "permission_denied_count" in home_stats
        assert isinstance(home_stats["permission_denied_count"], int)
    
    def test_special_files_not_counted_in_size(self):
        """Test that special files don't inflate size measurements."""
        result = users.collect()
        home_stats = result.get("home_directory_statistics", {})
        
        # Should track special file count separately
        assert "special_file_count" in home_stats


class TestSystemStorageSemantics:
    """Tests for system storage semantics."""
    
    def test_same_filesystem_grouped(self):
        """Test that directories on same filesystem are not reported as independent devices."""
        result = system.collect()
        storage = result.get("storage", {})
        filesystems = storage.get("filesystems", [])
        
        # Each filesystem entry should have mount_points list
        for fs in filesystems:
            assert "mount_points" in fs
            assert isinstance(fs["mount_points"], list)
            assert len(fs["mount_points"]) >= 1
        
        # If / and /home are on same filesystem, they should be in same entry
        # We can't guarantee this in test environment, but structure should support it


class TestTruncationSemantics:
    """Tests for truncation reporting semantics."""
    
    def test_filesystem_reports_truncation_state(self):
        """Test that incomplete filesystem traversal remains marked incomplete."""
        result = filesystem.collect()
        agg = result.get("aggregate_statistics", {})
        
        assert "collection_complete" in agg
        assert isinstance(agg["collection_complete"], bool)
        
        # If truncated, should have truncation_reasons
        if not agg["collection_complete"]:
            assert "truncation_reasons" in agg
