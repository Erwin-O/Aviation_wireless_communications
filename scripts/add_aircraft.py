#!/usr/bin/env python3
import argparse, json, pathlib, time, re, shutil, sys

DB_PATH = pathlib.Path("config/aircraft_db.json")
HEX_RE  = re.compile(r"^[0-9a-fA-F]{6}$")

def load_db():
    if not DB_PATH.exists():
        return {"schema_version": 1, "generated_at": ts(), "source_notes": "Bootstrapped", "aircraft": []}
    return json.loads(DB_PATH.read_text(encoding="utf-8"))

def save_db(db, note="Manual edit"):
    db["generated_at"] = ts()
    if note:
        db["source_notes"] = note
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # backup
    if DB_PATH.exists():
        shutil.copy2(DB_PATH, DB_PATH.with_suffix(".json.bak"))
    DB_PATH.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")

def ts():
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def upsert(db, rec, overwrite=False):
    # normalize
    rec["icao24"] = rec["icao24"].lower()
    # find existing
    items = db.get("aircraft", [])
    for a in items:
        if a.get("icao24","").lower() == rec["icao24"]:
            if overwrite:
                a.update({k:v for k,v in rec.items() if v not in (None,"")})
                return "updated"
            else:
                return "exists"
    items.append(rec)
    db["aircraft"] = items
    return "added"

def main():
    ap = argparse.ArgumentParser(description="Add or update a single aircraft in config/aircraft_db.json")
    ap.add_argument("--icao24", required=True, help="Hex ICAO24, e.g. 44D4A3")
    ap.add_argument("--registration", help="Tail number, e.g. OO-ABC")
    ap.add_argument("--type-code", dest="type_code", help="e.g. C172, A320")
    ap.add_argument("--model", help="Model string, e.g. Cessna 172S")
    ap.add_argument("--operator", help="Operator name")
    ap.add_argument("--country", help="ISO country code, e.g. BE")
    ap.add_argument("--overwrite", action="store_true", help="Update existing record if present")
    ap.add_argument("--note", default="Manual add/update", help="Source note to store in DB metadata")
    args = ap.parse_args()

    if not HEX_RE.match(args.icao24):
        print("❌ --icao24 must be 6 hex chars (e.g. 44D4A3)")
        sys.exit(1)

    rec = {
        "icao24": args.icao24,
        "registration": args.registration,
        "type_code": args.type_code,
        "model": args.model,
        "operator": args.operator,
        "country": args.country,
    }

    db = load_db()
    action = upsert(db, rec, overwrite=args.overwrite)
    save_db(db, note=args.note)

    if action == "added":
        print(f"✅ Added {args.icao24.lower()}")
    elif action == "updated":
        print(f"✅ Updated {args.icao24.lower()}")
    else:
        print(f"ℹ️  {args.icao24.lower()} already exists (use --overwrite to update)")

if __name__ == "__main__":
    main()
