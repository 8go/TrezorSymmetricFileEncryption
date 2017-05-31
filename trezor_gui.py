from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from PyQt5.QtWidgets import QDialog, QListWidgetItem
from PyQt5.QtCore import Qt, QVariant

from ui_trezor_chooser_dialog import Ui_TrezorChooserDialog
from ui_trezor_pin_dialog import Ui_TrezorPinDialog
from ui_trezor_passphrase_dialog import Ui_TrezorPassphraseDialog

import encoding

"""
This is generic code that should work untouched accross all applications.
This code implements the Trezor IO in GUI mode.
It covers all 3 operations: Trezor choser, PIN entry,
Passphrase entry.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


class TrezorChooserDialog(QDialog, Ui_TrezorChooserDialog):

	def __init__(self, deviceMap):
		"""
		Create dialog and fill it with labels from deviceMap

		@param deviceMap: dict device string -> device label
		"""
		QDialog.__init__(self)
		self.setupUi(self)

		for deviceStr, label in deviceMap.items():
			item = QListWidgetItem(label)
			item.setData(Qt.UserRole, QVariant(deviceStr))
			self.trezorList.addItem(item)
		self.trezorList.setCurrentRow(0)

	def chosenDeviceStr(self):
		"""
		Returns device string of chosen Trezor
		in Py3: must return str, i.e. bytes; not unicode!
		"""
		itemData = self.trezorList.currentItem().data(Qt.UserRole)
		deviceStr = encoding.tobytes(itemData)
		return deviceStr


class TrezorPassphraseDialog(QDialog, Ui_TrezorPassphraseDialog):

	def __init__(self):
		QDialog.__init__(self)
		self.setupUi(self)

	def passphrase(self):
		return encoding.normalize_nfc(self.passphraseEdit.text())


class TrezorPinDialog(QDialog, Ui_TrezorPinDialog):

	def __init__(self):
		QDialog.__init__(self)
		self.setupUi(self)

		self.pb1.clicked.connect(self.pinpadPressed)
		self.pb2.clicked.connect(self.pinpadPressed)
		self.pb3.clicked.connect(self.pinpadPressed)
		self.pb4.clicked.connect(self.pinpadPressed)
		self.pb5.clicked.connect(self.pinpadPressed)
		self.pb6.clicked.connect(self.pinpadPressed)
		self.pb7.clicked.connect(self.pinpadPressed)
		self.pb8.clicked.connect(self.pinpadPressed)
		self.pb9.clicked.connect(self.pinpadPressed)

	def pin(self):
		return encoding.normalize_nfc(self.pinEdit.text())

	def pinpadPressed(self):
		sender = self.sender()
		objName = sender.objectName()
		digit = objName[-1]
		self.pinEdit.setText(self.pinEdit.text() + digit)
