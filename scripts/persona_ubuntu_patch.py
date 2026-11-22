#!/usr/bin/env python3
# Setzt in der cowrie-fs.pickle die Inline-Inhalte (A_CONTENTS) der Dateien, die
# die Persona verraten, auf kohaerentes Ubuntu 20.04 - passend zu uname und
# SSH-Banner (cfg [shell]/[ssh]). Grund: dieser cowrie-Fork bedient honeyfs nur
# fuer LEERE Pickle-Knoten; version/motd/issue haben Inline-Inhalt (Debian),
# honeyfs ueberschreibt die nicht. Daher direkt im Pickle.
#
# Reversibel: legt einmalig <pickle>.bak-persona an. --off stellt es wieder her.
# Idempotent: ueberschreibt immer mit den Zielwerten.
import sys, os, pickle

PICKLE = os.environ.get("FSPICKLE", "/home/cowrie/cowrie/src/cowrie/data/fs.pickle")
BAK = PICKLE + ".bak-persona"

A_NAME, A_TYPE, A_SIZE, A_CONTENTS = 0, 1, 4, 7
T_DIR = 1

UBUNTU = {
    "/proc/version":
        b"Linux version 5.4.0-150-generic (buildd@lcy02-amd64-003) "
        b"(gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) "
        b"#167-Ubuntu SMP Mon May 15 17:20:39 UTC 2023\n",
    "/etc/motd":
        b"Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)\n\n"
        b" * Documentation:  https://help.ubuntu.com\n"
        b" * Management:     https://landscape.canonical.com\n"
        b" * Support:        https://ubuntu.com/advantage\n\n",
    "/etc/issue": b"Ubuntu 20.04.6 LTS \\n \\l\n\n",
    "/etc/issue.net": b"Ubuntu 20.04.6 LTS\n",
    # /etc/os-release ist ein Symlink auf /usr/lib/os-release - dort den Inhalt
    # setzen (Pickle-Knoten hatte eine Liste statt Bytes -> cat gab leer aus).
    "/usr/lib/os-release":
        b'NAME="Ubuntu"\n'
        b'VERSION="20.04.6 LTS (Focal Fossa)"\n'
        b'ID=ubuntu\n'
        b'ID_LIKE=debian\n'
        b'PRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
        b'VERSION_ID="20.04"\n'
        b'HOME_URL="https://www.ubuntu.com/"\n'
        b'SUPPORT_URL="https://help.ubuntu.com/"\n'
        b'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        b'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        b'VERSION_CODENAME=focal\n'
        b'UBUNTU_CODENAME=focal\n',
}


def walk(node, path):
    nm = node[A_NAME]
    p = "/" if path == "" and nm == "/" else path.rstrip("/") + "/" + nm
    yield p, node
    if node[A_TYPE] == T_DIR and isinstance(node[A_CONTENTS], list):
        for c in node[A_CONTENTS]:
            yield from walk(c, p)


def main():
    off = len(sys.argv) > 1 and sys.argv[1] == "--off"
    if off:
        if not os.path.exists(BAK):
            print("Kein Backup vorhanden:", BAK)
            return 1
        with open(BAK, "rb") as f:
            data = f.read()
        with open(PICKLE, "wb") as f:
            f.write(data)
        print("fs.pickle aus Backup wiederhergestellt.")
        return 0

    with open(PICKLE, "rb") as f:
        raw = f.read()
    if not os.path.exists(BAK):
        with open(BAK, "wb") as f:
            f.write(raw)
        print("Backup angelegt:", BAK)
    fs = pickle.loads(raw)
    idx = {p: n for p, n in walk(fs, "")}
    changed = 0
    for path, content in UBUNTU.items():
        n = idx.get(path)
        if n is None:
            print("  WARN fehlt im Pickle:", path)
            continue
        n[A_CONTENTS] = content
        n[A_SIZE] = len(content)
        changed += 1
        print("  gesetzt:", path, "(%d bytes)" % len(content))
    with open(PICKLE, "wb") as f:
        pickle.dump(fs, f)
    print("Fertig, %d Knoten aktualisiert." % changed)
    # Verifikation
    fs2 = pickle.loads(open(PICKLE, "rb").read())
    idx2 = {p: n for p, n in walk(fs2, "")}
    ok = all(idx2[p][A_CONTENTS] == c for p, c in UBUNTU.items() if p in idx2)
    print("Verifikation:", "OK" if ok else "FEHLER")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
