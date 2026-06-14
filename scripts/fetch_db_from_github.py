#!/usr/bin/env python3
"""
Fetch aircraft_db.json from GitHub, or create an empty one if not found.
"""
import requests
import argparse
import json
import time
import pathlib

GH_RAW = "https://raw.githubusercontent.com"

def create_empty_db(out_path: str):
    data = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_notes": "Bootstrapped empty DB (no remote file found)",
        "aircraft": []
    }
    p = pathlib.Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"✅ Created new empty DB at {out_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True, help="GitHub username/org")
    ap.add_argument("--repo", required=True, help="Repository name")
    ap.add_argument("--branch", default="main", help="Branch to fetch from")
    ap.add_argument("--remote-path", default="config/aircraft_db.json", help="Path in repo")
    ap.add_argument("--out", default="config/aircraft_db.json", help="Local output path")
    args = ap.parse_args()

    url = f"{GH_RAW}/{args.owner}/{args.repo}/{args.branch}/{args.remote_path}"
    print(f"⬇️  Fetching {args.owner}/{args.repo}@{args.branch}:{args.remote_path}")

    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            content = r.text
            out_file = pathlib.Path(args.out)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            # backup if exists
            if out_file.exists():
                out_file.replace(out_file.with_suffix(out_file.suffix + ".bak"))
            out_file.write_text(content, encoding="utf-8")
            print(f"✅ Updated {args.out} from GitHub")
        else:
            print(f"⚠️ Remote file not found (HTTP {r.status_code}), creating empty DB instead…")
            create_empty_db(args.out)
    except Exception as e:
        print(f"❌ Error fetching: {e}")
        print("Creating empty DB locally…")
        create_empty_db(args.out)

if __name__ == "__main__":
    main()
