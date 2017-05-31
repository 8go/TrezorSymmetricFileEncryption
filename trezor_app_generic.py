from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import getpass
import logging

from trezorlib.client import ProtocolMixin
from trezorlib.transport_hid import HidTransport
from trezorlib.client import BaseClient  # CallException, PinException
from trezorlib import messages_pb2 as proto
from trezorlib.transport import ConnectionError

from trezor_gui import TrezorPassphraseDialog, TrezorPinDialog, TrezorChooserDialog

import encoding

"""
This is generic code that should work untouched accross all applications.

This code is written specifically such that both Terminal-only mode as well as
GUI mode are supported for all 3 operations: Trezor choser, PIN entry,
Passphrase entry.
Each of the windows can be turned on or off individually with the 3 flags:
readpinfromstdin, readpassphrasefromstdin, and readdevicestringfromstdin.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


"""
Utility function to bridge Py2 and Py3 incompatibilities.
Maps Py2 raw_input() to input() for Py2.
Py2: raw_input()
Py3: input()
sys.version_info[0]
"""
try:
	input = raw_input
except NameError:
	pass


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
			return proto.PassphraseAck(passphrase=str(self.passphrase))

		if self.readpassphrasefromstdin:
			# read passphrase from stdin
			try:
				passphrase = getpass.getpass(u"Please enter passphrase: ")
				passphrase = encoding.normalize_nfc(passphrase)
			except KeyboardInterrupt:
				sys.stderr.write(u"\nKeyboard interrupt: passphrase not read. Aborting.\n")
				sys.exit(3)
			except Exception as e:
				sys.stderr.write(u"Critical error: Passphrase not read. Aborting. (%s)" % e)
				sys.exit(3)
		else:
			dialog = TrezorPassphraseDialog()
			if not dialog.exec_():
				sys.exit(3)
			else:
				passphrase = dialog.passphrase()

		return proto.PassphraseAck(passphrase=passphrase)

	def callback_PinMatrixRequest(self, msg):
		if self.readpinfromstdin:
			# read PIN from stdin
			print(u"                  7  8  9")
			print(u"                  4  5  6")
			print(u"                  1  2  3")
			try:
				pin = getpass.getpass(u"Please enter PIN: ")
			except KeyboardInterrupt:
				sys.stderr.write(u"\nKeyboard interrupt: PIN not read. Aborting.\n")
				sys.exit(7)
			except Exception as e:
				sys.stderr.write(u"Critical error: PIN not read. Aborting. (%s)" % e)
				sys.exit(7)
		else:
			dialog = TrezorPinDialog()
			if not dialog.exec_():
				sys.exit(7)
			pin = dialog.pin()

		return proto.PinMatrixAck(pin=pin)

	def prefillPassphrase(self, passphrase):
		"""
		Instead of asking for passphrase, use this one
		"""
		if passphrase is not None:
			self.passphrase = encoding.normalize_nfc(passphrase)
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

	def __init__(self, readdevicestringfromstdin=False):
		self.readdevicestringfromstdin = readdevicestringfromstdin

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

		devices is a list of device
		A device is something like:
		in Py2:  ['0001:0008:00', '0001:0008:01']
		In Py3:  [b'0001:0008:00', b'0001:0008:01']

		@returns HidTransport object of selected device
		"""
		if not len(devices):
			raise RuntimeError(u"No Trezor connected!")

		if len(devices) == 1:
			try:
				return HidTransport(devices[0])
			except IOError:
				raise RuntimeError(u"Trezor is currently in use")

		# maps deviceId string to device label
		deviceMap = {}
		for device in devices:
			try:
				transport = HidTransport(device)
				client = QtTrezorClient(transport)
				label = client.features.label and client.features.label or "<no label>"
				client.close()

				deviceMap[device[0]] = label
			except IOError:
				# device in use, do not offer as choice
				continue

		if not deviceMap:
			raise RuntimeError(u"All connected Trezors are in use!")

		if self.readdevicestringfromstdin:
			print(u'Chose your Trezor device please. '
				'Devices currently in use are not listed:')
			ii = 0
			for device in deviceMap:
				print('%d  %s' % (ii, deviceMap[device]))
				ii += 1
			ii -= 1
			while True:
				inputstr = input(u"Please provide the number of the device "
					"chosen: (%d-%d, Carriage return to quit) " % (0, ii))

				if inputstr == '':
					raise RuntimeError(u"No Trezors device chosen! Quitting.")
				try:
					inputint = int(inputstr)
				except Exception:
					print(u'Wrong input. You must enter a number '
						'between %d and %d. Try again.' % (0, ii))
					continue
				if inputint < 0 or inputint > ii:
					print(u'Wrong input. You must enter a number '
						'between %d and %d. Try again.' % (0, ii))
					continue
				break
			# dictionaries are different in Py2 and Py3
			if sys.version_info[0] > 2:
				deviceStr = list(deviceMap.keys())[ii]
			else:
				deviceStr = deviceMap.keys()[ii]
		else:
			dialog = TrezorChooserDialog(deviceMap)
			if not dialog.exec_():
				raise RuntimeError(u"No Trezors device chosen! Quitting.")
			deviceStr = dialog.chosenDeviceStr()
		return HidTransport([deviceStr, None])


def setupTrezor(readdevicestringfromstdin=False, mlogger=None):
	"""
	setup Trezor,
	on error exit program
	"""
	try:
		if mlogger is not None:
			mlogger.log(u"Starting Trezor initialization", logging.DEBUG, u"Trezor Info")
		trezorChooser = TrezorChooser(readdevicestringfromstdin)
		trezor = trezorChooser.getDevice()
	except (ConnectionError, RuntimeError) as e:
		if mlogger is not None:
			mlogger.log(u"Connection to Trezor failed: %s" % e,
			logging.CRITICAL, u"Trezor Error")
		sys.exit(1)

	if trezor is None:
		if mlogger is not None:
			mlogger.log(u"No available Trezor found, quitting.",
				logging.CRITICAL, u"Trezor Error")
		sys.exit(1)
	return trezor
