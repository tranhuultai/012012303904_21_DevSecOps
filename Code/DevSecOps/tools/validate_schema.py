import json
import sys

import jsonschema


def main() -> int:
    if len(sys.argv) != 3:
        print("dùng: validate_schema.py <schema.json> <data.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as fh:
        schema = json.load(fh)
    with open(sys.argv[2], encoding="utf-8") as fh:
        data = json.load(fh)
    jsonschema.validate(data, schema)
    print(f"schema OK: {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
