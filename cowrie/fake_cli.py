# JustDNS: Fake Router-/DVR-CLI-Kommandos (Mirai/Gafgyt-Escape-Sequenz).
#
# IoT-Botnets tippen nach dem Login auf Router/DVR-Geraeten eine feste Sequenz,
# um aus der eingeschraenkten Hersteller-CLI in eine Linux-Shell zu springen:
#   enable ; system ; shell ; linuxshell
# Ohne diese Kommandos antwortet cowrie "command not found" (exit 127) und der
# Bot bricht ab - er merkt "falsches Geraet".
#
# enable/system: stiller Erfolg (exit 0) - echte Geraete geben hier keine Ausgabe.
# shell/linuxshell/enablelinuxshell: geben ein BusyBox-Banner aus. Genau dieses
# Banner ist das Signal, auf das der Loader wartet, um den erfolgreichen Wechsel
# in die Geraete-Shell zu erkennen. Ohne das Banner probiert der Bot alle
# Escape-Kommandos nacheinander durch und bricht dann ohne Nachladen ab.
#
# Reine Emulation, kein echter Shell-Wechsel, kein zusaetzlicher Zugriff. Der Bot
# bleibt in der cowrie-Fake-Shell und tippt danach seine Nachlade-Kommandos
# (busybox/wget/tftp), die wir mitschneiden.
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_cli_noop(HoneyPotCommand):
    """Router-/DVR-CLI-Escape (enable/system): nichts tun, exit 0."""

    def start(self) -> None:
        self.exit(0)


class Command_cli_shell(HoneyPotCommand):
    """shell/linuxshell: BusyBox-Banner als Shell-Wechsel-Signal, dann exit 0."""

    def start(self) -> None:
        self.write(
            "\n\nBusyBox v1.30.1 (2021-10-21 13:45:12 UTC) built-in shell (ash)\n"
            "Enter 'help' for a list of built-in commands.\n\n"
        )
        self.exit(0)


for _name in ("enable", "system"):
    commands[_name] = Command_cli_noop

for _name in ("shell", "linuxshell", "enablelinuxshell"):
    commands[_name] = Command_cli_shell
