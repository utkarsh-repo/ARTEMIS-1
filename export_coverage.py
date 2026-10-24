#!/usr/bin/env python3
import argparse, csv, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(description="Export a coverage.json file to CSV")
    ap.add_argument("coverage", help="Path to runs/<run-id>/coverage.json")
    ap.add_argument("--out",default="coverage.csv")
    args=ap.parse_args()
    data=json.loads(Path(args.coverage).read_text(encoding="utf-8"))
    with Path(args.out).open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=["framework","id","name","coverage_design","result","tests","notes"])
        writer.writeheader()
        for row in data:
            row=dict(row); row["tests"]=";".join(row.get("tests",[]))
            writer.writerow({k:row.get(k,"") for k in writer.fieldnames})
    print(f"Wrote {args.out} with {len(data)} coverage rows.")
if __name__=="__main__": main()
