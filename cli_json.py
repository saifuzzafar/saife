import asyncio
import json
import sys
from pathlib import Path
from dataclasses import asdict
from datetime import datetime
from enum import Enum

from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent))

from engine.orchestrator import run_full_scan
from nodes.observability import setup_tracing

setup_tracing()  # no-op unless SAIFE_ENABLE_TRACING=true


def _json_default(obj):
    """Handle types that dataclasses.asdict() leaves unconverted."""
    if isinstance(obj, BaseModel):
        return obj.model_dump()
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    raise TypeError(f"Type {type(obj)} is not JSON serializable")


def _on_progress(category: str, status: object, message: str) -> None:
    """Print real-time progress to stderr so the route can stream it to the UI."""
    status_val = status.value if hasattr(status, "value") else str(status)
    print(f"PROGRESS: [{category}] {status_val} — {message}", file=sys.stderr, flush=True)


def _on_category_result(category: str, result: object) -> None:
    """Stream each category's raw result to stderr as soon as it finishes."""
    payload = result.model_dump() if hasattr(result, "model_dump") else {}
    print(
        f"RESULT_PARTIAL: {json.dumps({'category': category, 'result': payload}, default=_json_default)}",
        file=sys.stderr, flush=True,
    )


async def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No target URL provided"}))
        sys.exit(1)

    target_url = sys.argv[1]
    scan_depth = sys.argv[2] if len(sys.argv) > 2 else "full"

    try:
        report = await run_full_scan(
            target_url=target_url,
            categories=None,
            max_concurrent=3,
            scan_depth=scan_depth,
            on_progress=_on_progress,
            on_category_result=_on_category_result,
        )
        print(json.dumps(asdict(report), default=_json_default))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)  # Exit 0 so shell || chain doesn't fall through to wrong Python


if __name__ == "__main__":
    asyncio.run(main())
