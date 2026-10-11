#!/usr/bin/env python3
"""Convert the pilot HTTP records of the ids-model project to ids-offline examples.

The records are the 1,000 requests selected from the CSIC 2010 data set
(ids-model/data/http-mini/requests.jsonl): 500 labelled normal and 500
labelled anomalous. This script writes them as two example files, one per
label, so the rule engine can be run on each group:

    python3 tools/csic_to_examples.py --out /tmp/csic
    go run ./cmd/ids-offline -requests /tmp/csic -summary

The label is used only to choose the output file. It is not written into the
examples and the engine never sees it.

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
    args = parser.parse_args()

    groups = {"normal": [], "anomalous": []}
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
            groups[record["label_name"]].append(example)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, examples in groups.items():
        with open(out / f"csic-{name}.json", "w", encoding="utf-8") as f:
            json.dump(examples, f, ensure_ascii=False)
        print(f"{len(examples)} {name} requests written to {out / f'csic-{name}.json'}")


if __name__ == "__main__":
    main()
