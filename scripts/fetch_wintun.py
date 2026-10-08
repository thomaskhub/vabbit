#!/usr/bin/env python3
"""Download Wintun (the Windows TUN driver vabbit.exe loads) and verify it.

    python3 scripts/fetch_wintun.py OUT_DIR

writes OUT_DIR/wintun-amd64.dll, wintun-arm64.dll and wintun-LICENSE.txt.
wintun.dll is redistributed unmodified under its Prebuilt Binaries License
(wintun-LICENSE.txt), see https://www.wintun.net.
"""
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

VERSION = "0.14.1"
URL = f"https://www.wintun.net/builds/wintun-{VERSION}.zip"
SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"


def main() -> None:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    data = urllib.request.urlopen(URL, timeout=60).read()
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        print(f"::error title=wintun::{URL} has SHA-256 {got}, want {SHA256}")
        sys.exit(1)
    z = zipfile.ZipFile(io.BytesIO(data))
    files = {
        "wintun/bin/amd64/wintun.dll": "wintun-amd64.dll",
        "wintun/bin/arm64/wintun.dll": "wintun-arm64.dll",
        "wintun/LICENSE.txt": "wintun-LICENSE.txt",
    }
    for src, dst in files.items():
        with open(os.path.join(out, dst), "wb") as f:
            f.write(z.read(src))
    print(f"wintun {VERSION} written to {out}")


if __name__ == "__main__":
    main()
