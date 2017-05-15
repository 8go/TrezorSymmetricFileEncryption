#!/usr/bin/env python

'''
Use TREZOR as a hardware device for symmetric file encryption

Usage: python TrezorSymmetricFileEncryption.py
Usage: python TrezorSymmetricFileEncryption.py --help

Source and readme is on www.github.com, search for TrezorSymmetricFileEncryption

'''

import sys
import logging
import getpass

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
	Mixin for input of Trezor PIN and passhprases.
	Works via both, terminal as well as PyQt GUI
	"""

	def __init__(self, *args, **kwargs):
		super(QtTrezorMixin, self).__init__(*args, **kwargs)
		self.passphrase = None
		self.readpinfromstdin = None
		self.readpassphrasefromstdin = None

	def callback_ButtonRequest(self, msg):
		return proto.ButtonAck()

	def callback_PassphraseRequest(self, msg):
		if self.passphrase is not None:
			return proto.PassphraseAck(passphrase=unicode(self.passphrase))

		if self.readpassphrasefromstdin:
			# read passphrase from stdin
			try:
				passphrase = getpass.getpass("Please enter passphrase: ")
				passphrase = unicode(passphrase)
			except KeyboardInterrupt:
				sys.stderr.write("\nKeyboard interrupt: passphrase not read. Aborting.\n")
				sys.exit(3)
			except Exception, e:
				sys.stderr.write("Critical error: Passphrase not read. Aborting. (%s)" % e)
				sys.exit(3)
		else:
			dialog = TrezorPassphraseDialog()
			if not dialog.exec_():
				sys.exit(3)
			else:
				passphrase = dialog.passphraseEdit.text()
				passphrase = unicode(passphrase)

		return proto.PassphraseAck(passphrase=passphrase)

	def callback_PinMatrixRequest(self, msg):
		if self.readpinfromstdin:
			# read PIN from stdin
			print "                  7  8  9"
			print "                  4  5  6"
			print "                  1  2  3"
			try:
				pin = getpass.getpass("Please enter PIN: ")
			except KeyboardInterrupt:
				sys.stderr.write("\nKeyboard interrupt: PIN not read. Aborting.\n")
				sys.exit(7)
			except Exception, e:
				sys.stderr.write("Critical error: PIN not read. Aborting. (%s)" % e)
				sys.exit(7)
		else:
			dialog = EnterPinDialog()
			if not dialog.exec_():
				sys.exit(7)
			pin = q2s(dialog.pin())

		return proto.PinMatrixAck(pin=pin)

	def prefillPassphrase(self, passphrase):
		"""
		Instead of asking for passphrase, use this one
		"""
		if passphrase is not None:
			self.passphrase = passphrase.decode("utf-8")
		else:
			self.passphrase = None

	def prefillReadpinfromstdin(self, readpinfromstdin=False):
		"""
		Specify if PIN should be read from stdin instead of from GUI
		@param readpinfromstdin: True to force it to read from stdin, False otherwise
		@type readpinfromstdin: C{bool}
		"""
		self.readpinfromstdin = readpinfromstdin

	def prefillReadpassphrasefromstdin(self, readpassphrasefromstdin=False):
		"""
		Specify if passphrase should be read from stdin instead of from GUI
		@param readpassphrasefromstdin: True to force it to read from stdin, False otherwise
		@type readpassphrasefromstdin: C{bool}
		"""
		self.readpassphrasefromstdin = readpassphrasefromstdin

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
	settings.settings2Gui(dialog, trezor)
	processing.reportLogging("Trezor label: %s" % trezor.features.label, logging.INFO,
		"Trezor IO", settings, logger, dialog)
	if not dialog.exec_():
		processing.reportLogging("Shutting down due to user request "
			"(Done/Quit was called).", logging.DEBUG,
			"GUI IO", settings, logger, None)
		sys.exit(4) # Esc or exception
	settings.gui2Settings(dialog,trezor)

# root

logging.basicConfig(stream=sys.stderr, level=basics.LOGGINGLEVEL)
logger = logging.getLogger('tsfe')

app = QtGui.QApplication(sys.argv)

settings = processing.Settings(logger) # initialize settings
# parse command line
processing.parseArgs(sys.argv[1:], settings, logger)

try:
	trezorChooser = TrezorChooser()
	trezor = trezorChooser.getDevice()
except (ConnectionError, RuntimeError), e:
	processing.reportLogging("Connection to Trezor failed: %s" % e.message,
		logging.CRITICAL, "Trezor Error", settings, logger)
	sys.exit(1)

if trezor is None:
	processing.reportLogging("No available Trezor found, quitting.",
		logging.CRITICAL, "Trezor Error", settings, logger)
	sys.exit(1)

trezor.clear_session()
trezor.prefillReadpinfromstdin(settings.RArg)
trezor.prefillReadpassphrasefromstdin(settings.AArg)
trezor.prefillPassphrase(settings.PArg)

fileMap = file_map.FileMap(trezor,logger)

# if everything is specified in the command line then do not call the GUI
if ((settings.PArg is None) or (len(settings.inputFiles) <= 0)) and (not settings.TArg):
	# something was not specified, so we call the GUI
	showGui(trezor, settings, fileMap, logger)
else:
	processing.reportLogging("Trezor label: %s" % trezor.features.label, logging.INFO,
		"Trezor IO", settings, logger, None)
	processing.reportLogging("Everything was specified or --terminal was set, "
		"hence the GUI will not be called.", logging.INFO,
		"Trezor IO", settings, logger, None)
	if settings.WArg:
		processing.reportLogging("The option `--wipe` is set. In case of "
			"encryption, the original plaintext files will "
			"be shredded after encryption. In case of decryption, "
			"the encrypted files will be shredded after decryption. "
			"Abort if you are uncertain or don't understand.", logging.WARNING,
			"Dangerous arguments", settings, logger, None)

	processing.processAll(trezor, settings, fileMap, logger, dialog=None)
	sys.exit(0)
