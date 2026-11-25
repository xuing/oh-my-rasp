"""Verify a new Java 8 native-stream component block in an existing JSONL spool."""
import argparse
import json
from pathlib import Path


def component_block(event, package):
    details = event.get("details") or {}
    return (event.get("event") == "ohmyrasp-detection"
            and event.get("action") == "block"
            and event.get("algorithm") == "java8_deserialization_gadget_class"
            and event.get("hook") == "ObjectInputStream.resolveClass"
            and details.get("decision_basis") == "resolved_class"
            and details.get("class") in (package + ".InvokerTransformer", package + ".InstantiateTransformer"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("offset", type=int, help="spool size before the observation")
    parser.add_argument("package", choices=("org.apache.commons.collections.functors",
                                            "org.apache.commons.collections4.functors"))
    args = parser.parse_args()
    with args.log.open("rb") as spool:
        spool.seek(args.offset)
        if not any(component_block(json.loads(line), args.package) for line in spool):
            raise SystemExit("Missing resolved invocation or instantiation transformer block in new events")


if __name__ == "__main__":
    main()
