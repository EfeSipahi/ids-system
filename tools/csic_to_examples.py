#!/usr/bin/env python3
"""Convert the pilot HTTP records of the ids-model project to ids-offline examples.

The records are the 1,000 requests selected from the CSIC 2010 data set
(ids-model/data/http-mini/requests.jsonl): 500 labelled normal and 500
labelled anomalous. This script writes them as two example files, one per
label, so the rule engine can be run on each group:

    python3 tools/csic_to_examples.py --out /tmp/csic
    go run ./cmd/ids-offline -requests /tmp/csic -summary

With --splits, the requests are also divided by the ids-model split of
each one (train, validation, test), into six files such as
csic-train-normal.json. Profiles are written from the training requests
only and measured on the others:

    python3 tools/csic_to_examples.py --splits --out /tmp/csic-splits

The label and the split are used only to choose the output file. They are
not written into the examples and the engine never sees them.

The output is not part of this repository: the data belongs to the ids-model
project and is only read here.
"""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Convert the CSIC pilot records to ids-offline examples.")
    parser.add_argument("--records", default="../ids-model/data/http-mini/requests.jsonl")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--splits", nargs="?", const="../ids-model/data/processed/http-mini-splits-v1/assignments.jsonl",
                        help="divide by split too, from this assignments file (default: the ids-model split v1)")
    args = parser.parse_args()

    split_of = {}
    if args.splits:
        with open(args.splits, encoding="utf-8") as f:
            for line in f:
                a = json.loads(line)
                split_of[a["sample_id"]] = a["split"]

    groups = {}
    with open(args.records, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            example = {
                "name": record["sample_id"],
                "method": record["method"],
                "uri": record["request_target"],
                "version": record["http_version"],
                "headers": record["headers"],
            }
            if record["body"]:
                example["body"] = record["body"]
            name = record["label_name"]
            if args.splits:
                name = split_of[record["sample_id"]] + "-" + name
            groups.setdefault(name, []).append(example)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, examples in sorted(groups.items()):
        with open(out / f"csic-{name}.json", "w", encoding="utf-8") as f:
            json.dump(examples, f, ensure_ascii=False)
        print(f"{len(examples)} {name} requests written to {out / f'csic-{name}.json'}")


if __name__ == "__main__":
    main()
