#!/usr/bin/env python3
"""Build a personal Ubuntu .deb on Linux or macOS; never install/start the VPN."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from myvpn.model import validate_profile
from myvpn.updates import validate_bootstrap

VERSION = "1.2.0"


def archive(files, epoch):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz", format=tarfile.GNU_FORMAT) as tar:
        directories = set()
        for name in files:
            directories.update(str(p) for p in Path(name).parents if str(p) != ".")
        for name in sorted(directories):
            info = tarfile.TarInfo("./" + name)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, epoch
            info.uname = info.gname = "root"
            tar.addfile(info)
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo("./" + name)
            info.size, info.mode, info.mtime = len(data), mode, epoch
            info.uname = info.gname = "root"
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def ar_member(name, data, epoch):
    header = f"{name + '/':<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode("ascii")
    assert len(header) == 60
    return header + data + (b"\n" if len(data) % 2 else b"")


def elf_check(data, arch, name):
    machine = {"amd64": 62, "arm64": 183}[arch]
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != machine:
        raise ValueError(f"{name}: нужен Linux ELF для {arch}; выполните fetch-cores.sh на Linux")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.profile is not None and not args.profile.is_file():
        parser.error("Указанный --profile не существует")
    if args.bootstrap is not None and not args.bootstrap.is_file():
        parser.error("Указанный --bootstrap не существует")
    profile_path = args.profile or ROOT.parent / "config/linux.json"
    if not profile_path.exists():
        profile_path = ROOT.parent / "config/example.json"
        print("Личного профиля нет: используется фиктивный example.json")
    profile = validate_profile(json.loads(profile_path.read_bytes()))
    bootstrap = None
    bootstrap_path = args.bootstrap or ROOT.parent / "config/linux-update.json"
    if bootstrap_path.exists():
        bootstrap = validate_bootstrap(json.loads(bootstrap_path.read_bytes()))
        if bootstrap["client"] != profile["client"]:
            raise ValueError("Клиент bootstrap не совпадает с профилем")
    files = {}

    def add(name, source, mode=0o644):
        files[name] = (source.read_bytes() if isinstance(source, Path) else source.encode(), mode)

    for source in sorted((ROOT / "myvpn").glob("*.py")):
        add("usr/lib/myvpn/myvpn/" + source.name, source)
    for name in ("xray", "amneziawg-go", "awg"):
        source = ROOT / "vendor" / args.arch / name
        elf_check(source.read_bytes(), args.arch, name)
        add("usr/lib/myvpn/" + name, source, 0o755)
    add("usr/lib/myvpn/myvpn-helper", ROOT / "packaging/myvpn-helper", 0o755)
    add("usr/bin/myvpn", "#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0, '/usr/lib/myvpn')\nfrom myvpn.gui import main\nraise SystemExit(main())\n", 0o755)
    add("usr/share/myvpn/default_profile.json", json.dumps(profile, ensure_ascii=False) + "\n")
    if bootstrap:
        add("usr/share/myvpn/update_bootstrap.json", json.dumps(bootstrap) + "\n")
    add("usr/share/applications/myvpn.desktop", ROOT / "packaging/myvpn.desktop")
    add("usr/share/icons/hicolor/scalable/apps/myvpn.svg", ROOT / "packaging/myvpn.svg")
    add("usr/lib/systemd/system/myvpn-client.service", ROOT / "packaging/myvpn-client.service")
    add("usr/share/polkit-1/actions/org.myvpn.manage.policy", ROOT / "packaging/org.myvpn.manage.policy")
    for source in sorted((ROOT / "vendor" / args.arch).glob("LICENSE*")):
        add("usr/share/doc/myvpn/" + source.name, source)
    add("usr/share/doc/myvpn/README", ROOT / "README.md")
    installed_size = sum(len(data) for data, _ in files.values()) // 1024 + 1
    control = f"""Package: myvpn
Version: {VERSION}-1
Architecture: {args.arch}
Maintainer: My VPN project <noreply@users.noreply.github.com>
Section: net
Priority: optional
Installed-Size: {installed_size}
Depends: python3 (>= 3.12), python3-gi, gir1.2-gtk-3.0, python3-cryptography, libc6 (>= 2.38), iproute2, systemd, systemd-resolved, pkexec, curl, ca-certificates
Homepage: https://github.com/Tigersmechom/my_vpn
Description: Personal VPN desktop client for Ubuntu 24.04
 Native GTK interface for VLESS, Hysteria 2, AmneziaWG and compatible Xray modes.
 Authenticated configuration updates. Starts only on explicit user request.
"""
    controls = {"control": (control.encode(), 0o644)}
    for name in ("postinst", "prerm", "postrm"):
        controls[name] = ((ROOT / "packaging" / name).read_bytes(), 0o755)
    controls["md5sums"] = ("".join(f"{hashlib.md5(data).hexdigest()}  {name}\n" for name, (data, _) in sorted(files.items())).encode(), 0o644)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1792195200"))
    result = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n", epoch)
    result += ar_member("control.tar.xz", archive(controls, epoch), epoch)
    result += ar_member("data.tar.xz", archive(files, epoch), epoch)
    destination = args.output or ROOT.parent / f"dist/MyVPN-{VERSION}-ubuntu24.04-{args.arch}.deb"
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".myvpn-deb-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(result)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Готово: {destination} ({len(result):,} байт)")
    print("Персональный пакет содержит ключи VPN; не публикуйте его в открытом репозитории.")


if __name__ == "__main__":
    main()
