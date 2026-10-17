#!/usr/bin/env python3
"""Validate generated client configs without starting a tunnel or changing network state."""
import json
import pathlib
import subprocess
import tempfile
import sys

root = pathlib.Path(__file__).resolve().parents[1]
profile = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root.parent / "config/mac.json"
if not profile.exists():
    profile = root.parent / "config/example.json"
with tempfile.TemporaryDirectory(prefix="myvpn-config-check-") as directory:
    temporary = pathlib.Path(directory)
    subprocess.run([
        "swiftc", "-target", "arm64-apple-macosx13.0",
        str(root / "Sources/MyVPN/Profile.swift"),
        str(root / "Sources/MyVPN/Configs.swift"),
        str(root / "Sources/MyVPN/ProfileValidation.swift"),
        str(root / "Sources/MyVPN/RemoteUpdates.swift"),
        str(root / "Sources/MyVPN/Store.swift"),
        str(root / "Tests/ConfigChecks.swift"),
        str(root / "Tests/UpdateChecks.swift"),
        "-o", str(temporary / "check"),
    ], check=True)
    subprocess.run([str(temporary / "check"), str(profile), directory, str(root.parent)], check=True)
    for config in sorted(temporary.glob("*.json")):
        protocol = config.stem
        # Match the helper's system-plist extraction and its TUN wrapper.
        outbounds = subprocess.check_output(["/usr/bin/plutil", "-extract", "outbounds", "json", "-o", "-", str(config)])
        routing = subprocess.check_output(["/usr/bin/plutil", "-extract", "routing", "json", "-o", "-", str(config)])
        wrapped = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "tun", "port": 0, "protocol": "tun", "settings": {
                "name": "utun199", "mtu": 1500,
                "autoSystemRoutingTable": ["0.0.0.0/1", "128.0.0.0/1"],
            }}],
            "outbounds": json.loads(outbounds), "routing": json.loads(routing),
        }
        config.write_text(json.dumps(wrapped))
        result = subprocess.run([str(root / "vendor/xray"), "run", "-test", "-c", str(config)], capture_output=True)
        if result.returncode:
            raise SystemExit(f"Xray config validation failed for {protocol}; details withheld to protect credentials")
        print(f"{protocol}: bundled Xray accepted generated TUN config")
