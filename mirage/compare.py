"""Structural comparison of two MIRAGE snapshots.

This is a purely descriptive diff: it reports which measurements were added,
removed, or changed between two snapshots. It does not interpret differences,
score, or classify anything (consistent with MIRAGE's measurement-only scope).
"""

from typing import Any, Iterable

# Metadata fields that differ on every run and are not measurements.
DEFAULT_IGNORED = ("metadata.collected_at", "metadata.notes")


def flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts/lists into ``{"a.b.0.c": leaf}`` form."""
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        if not data:
            out[prefix] = data
        for key, value in data.items():
            out.update(flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(data, list):
        if not data:
            out[prefix] = data
        # Short scalar lists are kept whole so ordering changes are one diff.
        elif all(not isinstance(v, (dict, list)) for v in data):
            out[prefix] = data
        else:
            for i, value in enumerate(data):
                out.update(flatten(value, f"{prefix}.{i}"))
    else:
        out[prefix] = data
    return out


def diff_snapshots(
    a: dict[str, Any],
    b: dict[str, Any],
    ignore: Iterable[str] = DEFAULT_IGNORED,
) -> dict[str, Any]:
    """Compare two snapshot dicts.

    Returns a dict with ``added``, ``removed``, ``changed`` and ``unchanged_count``.
    Numeric changes include a ``delta``.
    """
    ignored = tuple(ignore)
    fa, fb = flatten(a), flatten(b)

    def skip(path: str) -> bool:
        return any(path == i or path.startswith(i + ".") for i in ignored)

    added = {k: fb[k] for k in sorted(fb.keys() - fa.keys()) if not skip(k)}
    removed = {k: fa[k] for k in sorted(fa.keys() - fb.keys()) if not skip(k)}
    changed: dict[str, dict[str, Any]] = {}
    unchanged = 0

    for key in sorted(fa.keys() & fb.keys()):
        if skip(key):
            continue
        va, vb = fa[key], fb[key]
        if va == vb:
            unchanged += 1
            continue
        entry: dict[str, Any] = {"from": va, "to": vb}
        numeric = (int, float)
        if (
            isinstance(va, numeric) and isinstance(vb, numeric)
            and not isinstance(va, bool) and not isinstance(vb, bool)
        ):
            entry["delta"] = vb - va
        changed[key] = entry

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged_count": unchanged,
    }


def format_diff(result: dict[str, Any]) -> str:
    """Render a diff result as readable text."""
    lines: list[str] = []
    for key, value in result["added"].items():
        lines.append(f"+ {key}: {value!r}")
    for key, value in result["removed"].items():
        lines.append(f"- {key}: {value!r}")
    for key, entry in result["changed"].items():
        delta = f" (delta {entry['delta']:+g})" if "delta" in entry else ""
        lines.append(f"~ {key}: {entry['from']!r} -> {entry['to']!r}{delta}")
    lines.append(
        f"\n{len(result['added'])} added, {len(result['removed'])} removed, "
        f"{len(result['changed'])} changed, {result['unchanged_count']} unchanged"
    )
    return "\n".join(lines)
