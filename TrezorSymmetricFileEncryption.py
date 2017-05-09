#!/usr/bin/env python

'''
Use TREZOR as a hardware device for symmetric file encryption

Usage: python TrezorSymmetricFileEncryption.py [-v] [-h] [-o | -e | -d] <files>

Source and readme is on www.github.com, search for TrezorSymmetricFileEncryption

'''

import sys
import logging

from PyQt4 import QtGui, QtCore
from PyQt4.QtCore import QTimer
from PyQt4.QtGui import QPixmap
from Crypto import Random
from shutil import copyfile

from trezorlib.client import BaseClient, ProtocolMixin, CallException, PinException
from trezorlib.transport import ConnectionError
from trezorlib.transport_hid import HidTransport
from trezorlib import messages_pb2 as proto

import file_map
from encoding import q2s, s2q

from dialogs import TrezorPassphraseDialog, Dialog, EnterPinDialog, TrezorChooserDialog

import basics
import processing

class QtTrezorMixin(object):
	"""
	Mixin for input of passhprases.
	"""

	def __init__(self, *args, **kwargs):
		super(QtTrezorMixin, self).__init__(*args, **kwargs)
		self.passphrase = None

	def callback_ButtonRequest(self, msg):
		return proto.ButtonAck()

	def callback_PassphraseRequest(self, msg):
		if self.passphrase is not None:
			return proto.PassphraseAck(passphrase=self.passphrase)

		dialog = TrezorPassphraseDialog()
		if not dialog.exec_():
			sys.exit(3)
		else:
			passphrase = dialog.passphraseEdit.text()
			passphrase = unicode(passphrase)

		return proto.PassphraseAck(passphrase=passphrase)

	def callback_PinMatrixRequest(self, msg):
		dialog = EnterPinDialog()
		if not dialog.exec_():
			sys.exit(7)

		pin = q2s(dialog.pin())
		return proto.PinMatrixAck(pin=pin)

	def prefillPassphrase(self, passphrase):
		"""
		Instead of asking for passphrase, use this one
		"""
		self.passphrase = passphrase.decode("utf-8")

class QtTrezorClient(ProtocolMixin, QtTrezorMixin, BaseClient):
	"""
	Trezor client with Qt input methods
	"""
	pass

class TrezorChooser(object):
	"""Class for working with Trezor device via HID"""

	def __init__(self):
		pass

	def getDevice(self):
		"""
		Get one from available devices. Widget will be shown if more
		devices are available.
		"""
		devices = self.enumerateHIDDevices()

		if not devices:
			return None

		transport = self.chooseDevice(devices)
		client = QtTrezorClient(transport)

		return client

	def enumerateHIDDevices(self):
		"""Returns Trezor HID devices"""
		devices = HidTransport.enumerate()

		return devices

	def chooseDevice(self, devices):
		"""
		Choose device from enumerated list. If there's only one Trezor,
		that will be chosen.

		If there are multiple Trezors, diplays a widget with list
		of Trezor devices to choose from.

		@returns HidTransport object of selected device
		"""
		if not len(devices):
			raise RuntimeError("No Trezor connected!")

		if len(devices) == 1:
			try:
				return HidTransport(devices[0])
			except IOError:
				raise RuntimeError("Trezor is currently in use")


		#maps deviceId string to device label
		deviceMap = {}
		for device in devices:
			try:
				transport = HidTransport(device)
				client = QtTrezorClient(transport)
				label = client.features.label and client.features.label or "<no label>"
				client.close()

				deviceMap[device[0]] = label
			except IOError:
				#device in use, do not offer as choice
				continue

		if not deviceMap:
			raise RuntimeError("All connected Trezors are in use!")

		dialog = TrezorChooserDialog(deviceMap)
		if not dialog.exec_():
			sys.exit(9)

		deviceStr = dialog.chosenDeviceStr()
		return HidTransport([deviceStr, None])

def showGui(trezor, settings, fileMap, logger):
	"""
	Initialize, ask for encrypt/decrypt options,
	ask for files to be decrypted/encrypted,
	ask for master passphrase = trezor passphrase.

	Makes sure a session is created on Trezor so that the passphrase
	will be cached until disconnect.

	@param trezor: Trezor client
	@param settings: Settings object to store command line arguments or
		items selected in GUI
	"""
	dialog = Dialog(trezor, settings, fileMap, logger)
	settings.guiExists = True
	settings.settings2Gui(dialog, trezor)
	if settings.logger.getEffectiveLevel() <= logging.INFO:
		dialog.appendDescription("<br>Trezor label: " + trezor.features.label)
	if not dialog.exec_():
		logger.debug("Shutting down due to user request (Done/Quit was called).")
		sys.exit(4) # Esc or exception
	settings.guiExists = False
	settings.gui2Settings(dialog,trezor)

# root

logging.basicConfig(stream=sys.stderr, level=basics.LOGGINGLEVEL)
logger = logging.getLogger('')

app = QtGui.QApplication(sys.argv)

settings = processing.Settings(logger) # initialize settings
# parse command line
processing.parseArgs(sys.argv[1:], settings, logger)

try:
	trezorChooser = TrezorChooser()
	trezor = trezorChooser.getDevice()
except (ConnectionError, RuntimeError), e:
	if settings.TArg:
		logger.critical("Connection to Trezor failed: %s", e.message)
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
			"Trezor error", "Error: Connection to Trezor failed: " + e.message)
		msgBox.exec_()
	sys.exit(1)

if trezor is None:
	if settings.TArg:
		logger.critical("No available Trezor found, quitting.")
	else:
		msgBox = QtGui.QMessageBox(QtGui.QMessageBox.Critical,
			"Trezor error", "No available Trezor found, quitting.")
		msgBox.exec_()
	sys.exit(1)

trezor.clear_session()

if settings.TArg:
	logger.info("Trezor label: %s", trezor.features.label)

fileMap = file_map.FileMap(trezor,logger)

# if everything is specified in the command line then do not call the GUI
if ((settings.PArg is None) or (len(settings.inputFiles) <= 0)) and (not settings.TArg):
	# something was not specified, so we call the GUI
	showGui(trezor, settings, fileMap, logger)
else:
	logger.info("Everything was specified or --terminal was set, "
		"hence the GUI will not be called.")
	if settings.PArg is None:
		settings.PArg = ""

	feedback = processing.Feedback()
	processing.processAll(trezor, settings, fileMap, logger, feedback)
	sys.exit(0)
