"""Snapshot model for MIRAGE environment profiles.

Provides schema versioning, metadata tracking, and structured output.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional
from pathlib import Path

# Schema version for this release
SCHEMA_VERSION = "1.0.0"


class Snapshot:
    """Represents a complete environment snapshot.
    
    A Snapshot contains all collected measurements along with metadata
    about the collection process itself.
    """
    
    def __init__(self):
        """Initialize an empty snapshot."""
        self._data: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "metadata": {},
            "collectors": {},
            "errors": [],
        }
    
    def set_metadata(
        self,
        collector_name: Optional[str] = None,
            collector_version: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Set collection metadata.
        
        Args:
            collector_name: Name of the collecting tool (default: "mirage")
            collector_version: Version of the collecting tool
            notes: Optional free-form notes about the collection
        
        Notes:
            - Hostname is intentionally NOT collected (privacy concern)
        """
        self._data["metadata"] = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collector_name": collector_name or "mirage",
            "collector_version": collector_version or "0.2.0",
            "notes": notes,
        }
    
    def add_collector_result(
        self,
        name: str,
        result: dict[str, Any],
    ) -> None:
        """Add a collector's results to the snapshot.
        
        Args:
            name: Name of the collector (e.g., "system", "users")
            result: Dictionary containing the collector's measurements
        """
        self._data["collectors"][name] = result
        
        # Extract any errors from the collector result
        if "errors" in result and result["errors"]:
            for error in result["errors"]:
                self._data["errors"].append(f"{name}: {error}")
    
    def get_data(self) -> dict[str, Any]:
        """Get the snapshot data as a dictionary.
        
        Returns:
            Complete snapshot dictionary including metadata and all collector results.
        """
        return self._data.copy()
    
    def to_json(self, indent: int = 2, sort_keys: bool = False) -> str:
        """Serialize the snapshot to JSON string.
        
        Args:
            indent: Number of spaces for indentation (default: 2)
            sort_keys: Whether to sort keys alphabetically (default: False)
        
        Returns:
            JSON string representation of the snapshot.
        """
        return json.dumps(self._data, indent=indent, sort_keys=sort_keys, default=str)
    
    def save(self, path: str | Path, indent: int = 2) -> None:
        """Save the snapshot to a JSON file.
        
        Args:
            path: File path to save to
            indent: Number of spaces for indentation (default: 2)
        
        Raises:
            OSError: If the file cannot be written
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=indent, default=str)
    
    @classmethod
    def from_file(cls, path: str | Path) -> "Snapshot":
        """Load a snapshot from a JSON file.
        
        Args:
            path: File path to load from
        
        Returns:
            Snapshot object loaded from the file
        
        Raises:
            FileNotFoundError: If the file does not exist
            json.JSONDecodeError: If the file is not valid JSON
        """
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        snapshot = cls()
        snapshot._data = data
        return snapshot
    
    @classmethod
    def from_json(cls, json_str: str) -> "Snapshot":
        """Load a snapshot from a JSON string.
        
        Args:
            json_str: JSON string to parse
        
        Returns:
            Snapshot object parsed from the string
        
        Raises:
            json.JSONDecodeError: If the string is not valid JSON
        """
        data = json.loads(json_str)
        snapshot = cls()
        snapshot._data = data
        return snapshot
    
    def validate(self) -> list[str]:
        """Validate the snapshot structure.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors: list[str] = []

        if not isinstance(self._data, dict):
            return ["Snapshot root must be a dictionary"]
        
        # Check required top-level keys
        required_keys = ["schema_version", "metadata", "collectors"]
        for key in required_keys:
            if key not in self._data:
                errors.append(f"Missing required key: {key}")
        
        # Validate schema version format
        schema_ver = self._data.get("schema_version", "")
        if not schema_ver:
            errors.append("Schema version is empty")
        elif not isinstance(schema_ver, str):
            errors.append("Schema version must be a string")
        
        # Validate metadata
        metadata = self._data.get("metadata", {})
        if not isinstance(metadata, dict):
            errors.append("Metadata must be a dictionary")
        elif "collected_at" not in metadata:
            errors.append("Missing collected_at timestamp in metadata")
        
        # Validate collectors
        collectors = self._data.get("collectors", {})
        if not isinstance(collectors, dict):
            errors.append("Collectors must be a dictionary")
        
        return errors
    
    def __repr__(self) -> str:
        """Return a string representation of the snapshot."""
        collector_count = len(self._data.get("collectors", {}))
        error_count = len(self._data.get("errors", []))
        return f"Snapshot(schema_version={self._data.get('schema_version')!r}, collectors={collector_count}, errors={error_count})"
