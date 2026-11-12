import sys
import json
from pathlib import Path
from dataclasses import asdict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from nodes.memory_store import get_memory


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


memory = get_memory()

if len(sys.argv) > 1 and sys.argv[1] == '--clear':
    memory.clear_history()
    print(json.dumps({'cleared': True}))
else:
    target_url = sys.argv[1] if len(sys.argv) > 1 else None
    history = memory.get_history(target_url=target_url, limit=50)
    print(json.dumps([asdict(r) for r in history], default=_json_default))
