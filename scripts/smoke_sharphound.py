#!/usr/bin/env python3
"""Offline contract checks for SharpHound metadata preservation."""

from __future__ import annotations

import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sharphound_parser import parse_zip_bytes


def main() -> int:
    user_sid = "S-1-5-21-1-1-1-1101"
    computer_sid = "S-1-5-21-1-1-1-2101"
    group_sid = "S-1-5-21-1-1-1-3101"
    files = {
        "users.json": {"data": [{
            "ObjectIdentifier": user_sid,
            "Properties": {
                "name": "JDOE@EXAMPLE.COM",
                "displayname": "Jane Doe",
                "title": "Security Engineer",
                "company": "Example Corp",
                "manager": "S-1-5-21-1-1-1-1100",
            },
        }]},
        "computers.json": {"data": [{
            "ObjectIdentifier": computer_sid,
            "Properties": {"name": "WEB01.EXAMPLE.COM", "managedby": user_sid},
        }]},
        "groups.json": {"data": [{
            "ObjectIdentifier": group_sid,
            "Properties": {"name": "WEB ADMINS@EXAMPLE.COM", "managedBy": user_sid},
        }]},
    }
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, json.dumps(value))

    result = parse_zip_bytes(payload.getvalue())
    entities = {entity.temp_id: entity for entity in result.entities}
    checks = [
        (entities[user_sid].properties["title"] == "Security Engineer", "user title preserved"),
        (entities[user_sid].properties["company"] == "Example Corp", "user company preserved"),
        (entities[user_sid].properties["manager"] == "S-1-5-21-1-1-1-1100", "user manager preserved"),
        (entities[computer_sid].properties["managed_by"] == user_sid, "computer managedBy preserved"),
        (entities[group_sid].properties["managed_by"] == user_sid, "group managedBy preserved"),
    ]
    failed = False
    for passed, label in checks:
        print(("PASS" if passed else "FAIL") + ": " + label)
        failed |= not passed
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())