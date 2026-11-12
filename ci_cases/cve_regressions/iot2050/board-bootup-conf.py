#!/usr/bin/env python3
# CVE-2026-109830 — Siemens meta-iot2050 board-conf-tools
# board-bootup-conf.py:90 — initMode/terminateOpt come from
# board-configuration.json (attacker-writable device config) and are
# concatenated into a shell=True subprocess call unchecked.
import sys
import subprocess
from json_ops.json_ops import BoardConfigurationUtility

board_conf = BoardConfigurationUtility('board-conf-tools/json_ops/board-configuration.json')


def initExternalSerialMode():
    initMode = board_conf.getExternalDB9InitMode()
    currentMode = board_conf.getExternalDB9CurrenttMode()
    terminate = board_conf.getExternalRs485TerminalteConf()

    if initMode != currentMode:
        board_conf.setExternalDB9CurrentMode(initMode)
        board_conf.saveConfig()

    terminateOpt = ''
    if (initMode == 'RS485') or (initMode == 'RS422'):
        terminateOpt = ' -t' if terminate == 'on' else ''
    # VULNERABLE (CVE-2026-109830): config-file value concatenated into shell
    subprocess.call("switchserialmode -m " +
                    initMode + terminateOpt, shell=True)


def safeReboot():
    # SAFE control: argument-list form, no shell, no config input
    subprocess.call(['systemctl', 'reboot'], shell=False)


if __name__ == '__main__':
    initExternalSerialMode()
