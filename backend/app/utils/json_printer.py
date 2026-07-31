import json
from dataclasses import asdict, is_dataclass


def convert_to_json(obj):
    
    #Convert dataclasses and nested structures into JSON compatible data.
    

    if is_dataclass(obj):
        return asdict(obj)

    if isinstance(obj, list):
        return [convert_to_json(item) for item in obj]

    if isinstance(obj, dict):
        return {
            key: convert_to_json(value)
            for key, value in obj.items()
        }

    return obj


def print_json(obj) -> None:
    
    #Pretty-print objects as formatted JSON.
    

    json_ready = convert_to_json(obj)

    print(
        json.dumps(
            json_ready,
            indent=4,
            default=str
        )
    )