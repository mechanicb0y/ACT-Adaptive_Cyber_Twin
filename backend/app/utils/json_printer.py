import json
from dataclasses import asdict, is_dataclass


def print_json(obj) -> None:

    if is_dataclass(obj):
        obj = asdict(obj)

    print(json.dumps(obj, indent=4, default=str))