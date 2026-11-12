#! /usr/bin/env python3
#
# Copyright (c) Siemens AG, 2023
#
# This file is subject to the terms and conditions of the MIT License.  See
# COPYING.MIT file in the top-level directory.

import json
from collections import OrderedDict
import os


class BoardConfigurationUtility:
    def __init__(self):
        basepath = os.path.abspath(__file__)
        folder = os.path.dirname(basepath)
        self.configureFile = os.path.join(folder, 'board-configuration.json')
        self.config = self.getConfig()
        self.arduino_pinmux_map = self.config['Arduino_pinmux_map']
        self.arduino_io_mux = self.config['Arduino_io_mux']
        self.arduino_io_do_not_touch = self.config.setdefault(
            'Arduino_io_do_not_touch',
            OrderedDict(('IO' + str(i) + '_DO_NOT_TOUCH', False) for i in range(0, 20)))
        self.arduino_io_pull_mode = self.config['Arduino_io_pull_mode']
        self.external_db9_serial_config = self.config['External_db9_serial']

    def getConfig(self):
        with open(self.configureFile, 'r') as f:
            config = json.load(f, object_pairs_hook=OrderedDict)
            return config

    def saveConfig(self):
        with open(self.configureFile, 'w') as f:
            json.dump(self.config, f, indent=4, separators=(',', ': '))

    def getExternalDB9InitMode(self):
        return self.external_db9_serial_config['External_Serial_Init_Mode']

    def setExternalDB9InitMode(self, initMode):
        self.external_db9_serial_config['External_Serial_Init_Mode'] = initMode

    def getExternalDB9CurrenttMode(self):
        return self.external_db9_serial_config['External_Serial_Current_Mode']

    def setExternalDB9CurrentMode(self, currentMode):
        self.external_db9_serial_config['External_Serial_Current_Mode'] = currentMode

    def getExternalRs485TerminalteConf(self):
        return self.external_db9_serial_config['External_Serial_Terminate']

    def setExternalRs485TerminalteConf(self, terminate):
        self.external_db9_serial_config['External_Serial_Terminate'] = terminate

    def arduinoPinmuxMap(self, index):
        return self.arduino_pinmux_map['IO' + str(index)]

    def getArduinoPinmuxCfg(self, index):
        return self.arduino_io_mux['IO' + str(index) + '_MUX']

    def getArduinoIoDoNotTouch(self, index):
        return self.arduino_io_do_not_touch['IO' + str(index) + '_DO_NOT_TOUCH']

    def setArduinoIoDoNotTouch(self, index, do_not_touch):
        self.arduino_io_do_not_touch['IO' + str(index) + '_DO_NOT_TOUCH'] = do_not_touch

    def _setPinmuxOfUserConfig(self, pinmux, index):
        self.arduino_io_mux['IO' + str(index) + '_MUX'] = pinmux

    def setArduinoPinmuxCfg(self, pinmux, index=None):
        if index is not None:
            self._setPinmuxOfUserConfig(pinmux, index)
        else:
            for i in range(0, 20):
                pinmuxes = self.arduinoPinmuxMap(i)
                if pinmux in ' '.join(pinmuxes):
                    self.setArduinoPullModeCfg(i, 'Hiz')
                    self._setPinmuxOfUserConfig([n for n in pinmuxes if pinmux in n][0], i)

    def checkPinmuxConfig(self, pinmux, index):
        if type(pinmux) == tuple or type(index) == tuple:
            if len(pinmux) != len(index):
                print("error")

            for i in range(len(pinmux)):
                if pinmux[i] != self.getArduinoPinmuxCfg(index[i]):
                    return 0
        elif pinmux not in self.getArduinoPinmuxCfg(index):
            return 0

        return 1

    def getDirection(self, index):
        if self.checkPinmuxConfig('GPIO_Input', index):
            return 'Input'
        elif self.checkPinmuxConfig('GPIO_Output', index):
            return 'Output'
        else:
            return '--'

    def setArduinoPullModeCfg(self, index, pullMode):
        self.arduino_io_pull_mode['IO' + str(index) + '_PULL_MODE'] = pullMode

    def getArduinoPullModeCfg(self, index):
        return self.arduino_io_pull_mode['IO' + str(index) + '_PULL_MODE']
