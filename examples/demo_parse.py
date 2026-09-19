"""
Quick demo: parse the vulnerable-api spec and print a normalized view.

Run:
    python3 examples/demo_parse.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parser.openapi_parser import parse_openapi_spec  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"


def main():
    spec = parse_openapi_spec(SPEC_PATH)
    print(f"API: {spec.title} v{spec.version}")
    print(f"Endpoints discovered: {spec.endpoint_count()}\n")

    for ep in spec.endpoints:
        auth = ", ".join(ep.security.scheme_names) if ep.security.scheme_names else "NONE DECLARED"
        print(f"{ep.method:6} {ep.path}")
        print(f"    security: {auth}")
        if ep.path_parameters:
            for p in ep.path_parameters:
                print(f"    path param: {p.name} ({p.schema_.type}, required={p.required})")
        if ep.request_body:
            for f in ep.request_body.fields:
                print(f"    body field: {f.name} ({f.schema_.type}, required={f.required})")
        print()


if __name__ == "__main__":
    main()
