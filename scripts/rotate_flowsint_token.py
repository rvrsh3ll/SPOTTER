#!/usr/bin/env python3
"""Rotate Flowsint API JWT token before expiration.

The Flowsint JWT token expires every ~60 hours (ACCESS_TOKEN_EXPIRE_MINUTES).
This script checks if the current token is about to expire and rotates it
automatically by:
1. Minting a new token via POST /api/auth/token
2. Storing it in the SOPS-encrypted machine tier
3. Recreating containers so the new token bakes in

Usage:
    # Check and rotate if needed (safe to run via cron)
    sudo python3 scripts/rotate_flowsint_token.py

    # Force rotation even if token is not expired
    sudo python3 scripts/rotate_flowsint_token.py --force

    # Check expiration only (no rotation)
    python3 scripts/rotate_flowsint_token.py --check

Environment:
    FLOWSINT_ADMIN_EMAIL    Flowsint admin email (default: rvrsh3ll@gmail.com)
    FLOWSINT_ADMIN_PASSWORD Flowsint admin password (REQUIRED)
    FLOWSINT_API_URL        Flowsint API URL (default: http://127.0.0.1:5001)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload (middle part) without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    payload_b64 = parts[1]
    # Add padding if needed
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_json = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_json)


def get_token_expiration(token: str) -> datetime:
    """Get expiration time from JWT token."""
    payload = decode_jwt_payload(token)
    exp_timestamp = payload.get("exp")
    if not exp_timestamp:
        raise ValueError("JWT has no expiration claim")
    return datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)


def get_current_token() -> str | None:
    """Get current FLOWSINT_API_KEY from SOPS-encrypted tier."""
    try:
        result = subprocess.run(
            ["sudo", "sops", "-d", "secrets/machine.sops.env"],
            cwd="/home/user/SPOTTER",
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.splitlines():
            if line.startswith("FLOWSINT_API_KEY="):
                return line.split("=", 1)[1].strip()
    except subprocess.CalledProcessError:
        pass
    return None


def mint_new_token(api_url: str, email: str, password: str) -> str:
    """Mint new Flowsint JWT token via /api/auth/token."""
    resp = requests.post(
        f"{api_url}/api/auth/token",
        data={"username": email, "password": password},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token") or data.get("token")
    if not token:
        raise RuntimeError(f"No token in response: {data}")
    return token


def store_token_in_sops(token: str) -> None:
    """Store token in SOPS-encrypted machine tier."""
    # Use spotter_secret.py to store in machine tier
    result = subprocess.run(
        [
            "sudo",
            "python3",
            "scripts/spotter_secret.py",
            "set",
            "--stdin",
            "--tier",
            "machine",
            "FLOWSINT_API_KEY",
        ],
        input=token,
        cwd="/home/user/SPOTTER",
        capture_output=True,
        text=True,
        check=True,
    )
    print(result.stdout)


def recreate_containers() -> None:
    """Recreate n8n, task-runners, and open-webui containers."""
    result = subprocess.run(
        [
            "sudo",
            "scripts/spotter_compose.sh",
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "n8n",
            "task-runners",
            "open-webui",
        ],
        cwd="/home/user/SPOTTER",
        capture_output=True,
        text=True,
        check=True,
    )
    print(result.stdout)


def check_expiration(token: str, warn_hours: int = 24) -> tuple[bool, str]:
    """Check if token is expired or about to expire.
    
    Returns (should_rotate, message).
    """
    try:
        exp_time = get_token_expiration(token)
        now = datetime.now(timezone.utc)
        remaining = exp_time - now
        remaining_hours = remaining.total_seconds() / 3600
        
        if remaining.total_seconds() <= 0:
            return True, f"Token EXPIRED at {exp_time.isoformat()}"
        elif remaining_hours < warn_hours:
            return True, f"Token expires in {remaining_hours:.1f} hours (at {exp_time.isoformat()})"
        else:
            return False, f"Token valid for {remaining_hours:.1f} hours (expires {exp_time.isoformat()})"
    except Exception as e:
        return True, f"Failed to decode token: {e}"


def main():
    parser = argparse.ArgumentParser(description="Rotate Flowsint API JWT token")
    parser.add_argument("--force", action="store_true", help="Force rotation even if token is valid")
    parser.add_argument("--check", action="store_true", help="Check expiration only (no rotation)")
    parser.add_argument("--warn-hours", type=int, default=24, help="Warn if token expires within this many hours (default: 24)")
    parser.add_argument("--api-url", default=os.environ.get("FLOWSINT_API_URL", "http://127.0.0.1:5001"))
    parser.add_argument("--email", default=os.environ.get("FLOWSINT_ADMIN_EMAIL", "rvrsh3ll@gmail.com"))
    parser.add_argument("--password", default=os.environ.get("FLOWSINT_ADMIN_PASSWORD", ""))
    args = parser.parse_args()
    
    # Get current token
    current_token = get_current_token()
    if not current_token:
        print("⚠️  No FLOWSINT_API_KEY found in SOPS-encrypted tier")
        if args.check:
            sys.exit(1)
        print("Will mint new token...")
    else:
        # Check expiration
        should_rotate, message = check_expiration(current_token, args.warn_hours)
        print(f"Current token: {message}")
        
        if args.check:
            sys.exit(0 if not should_rotate else 1)
        
        if not should_rotate and not args.force:
            print("✅ No rotation needed")
            sys.exit(0)
    
    # Check if we have credentials
    if not args.password:
        print("❌ FLOWSINT_ADMIN_PASSWORD not set")
        print("Set it via environment variable or --password flag")
        sys.exit(1)
    
    # Mint new token
    print(f"Minting new token from {args.api_url}...")
    try:
        new_token = mint_new_token(args.api_url, args.email, args.password)
        print(f"✅ New token minted (length: {len(new_token)})")
    except Exception as e:
        print(f"❌ Failed to mint token: {e}")
        sys.exit(1)
    
    if args.check:
        sys.exit(0)
    
    # Store in SOPS
    print("Storing token in SOPS-encrypted machine tier...")
    try:
        store_token_in_sops(new_token)
        print("✅ Token stored")
    except Exception as e:
        print(f"❌ Failed to store token: {e}")
        sys.exit(1)
    
    # Recreate containers
    print("Recreating containers...")
    try:
        recreate_containers()
        print("✅ Containers recreated")
    except Exception as e:
        print(f"❌ Failed to recreate containers: {e}")
        sys.exit(1)
    
    print("✅ Token rotation complete!")


if __name__ == "__main__":
    main()
