#!/usr/bin/env python

'''
Use TREZOR as a hardware device for symmetric file encryption

Usage: python TrezorSymmetricFileEncryption.py
Usage: python TrezorSymmetricFileEncryption.py --help

Source and readme is on www.github.com, search for TrezorSymmetricFileEncryption

'''

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys
import logging
import codecs

from PyQt5.QtWidgets import QApplication  # for the clipboard and window

from dialogs import Dialog

import basics
import settings
import processing
from trezor_app_specific import FileMap
import trezor_app_generic

"""
The file with the main function.

Code should work on both Python 2.7 as well as 3.4.
Requires PyQt5.
(Old version supported PyQt4.)
"""


def showGui(trezor, dialog, settings):
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
	settings.settings2Gui(dialog)
	if not dialog.exec_():
		# Esc or exception or Quit/Close/Done
		settings.mlogger.log("Shutting down due to user request "
			"(Done/Quit was called).", logging.DEBUG, "GUI IO")
		# sys.exit(4)
	settings.gui2Settings(dialog)


def useTerminal(fileMap, settings):
	if settings.WArg:
		settings.mlogger.log("The option `--wipe` is set. In case of "
			"encryption, the original plaintext files will "
			"be shredded after encryption. In case of decryption, "
			"the encrypted files will be shredded after decryption. "
			"Abort if you are uncertain or don't understand.", logging.WARNING,
			"Dangerous arguments")
	processing.processAll(fileMap, settings, dialog=None)


def main():
	if sys.version_info[0] < 3:  # Py2-vs-Py3:
		# redirecting output to a file can cause unicode problems
		# read: https://stackoverflow.com/questions/5530708/
		# To fix it either run the scripts as: PYTHONIOENCODING=utf-8 python TrezorSymmetricFileEncryption.py
		# or add the following line of code.
		# Only shows up in python2 TrezorSymmetricFileEncryption.py >> log scenarios
		# Exception: 'ascii' codec can't encode characters in position 10-13: ordinal not in range(128)
		sys.stdout = codecs.getwriter('utf-8')(sys.stdout)

	app = QApplication(sys.argv)
	if app is None:  # just to get rid f the linter warning on above line
		print("Critical error: Qt cannot be initialized.")
	sets = settings.Settings()  # initialize settings
	# parse command line
	args = settings.Args(sets)
	args.parseArgs(sys.argv[1:])

	trezor = trezor_app_generic.setupTrezor(sets.TArg, sets.mlogger)
	# trezor.clear_session() ## not needed
	trezor.prefillReadpinfromstdin(sets.RArg)
	trezor.prefillReadpassphrasefromstdin(sets.AArg)
	if sets.PArg is None:
		trezor.prefillPassphrase(u'')
	else:
		trezor.prefillPassphrase(sets.PArg)

	# if everything is specified in the command line then do not call the GUI
	if ((sets.PArg is None) or (len(sets.inputFiles) <= 0)) and (not sets.TArg):
		dialog = Dialog(trezor, sets)
		sets.mlogger.setQtextbrowser(dialog.textBrowser)
		sets.mlogger.setQtextheader(dialog.descrHeader())
		sets.mlogger.setQtextcontent(dialog.descrContent())
		sets.mlogger.setQtexttrailer(dialog.descrTrailer())
	else:
		sets.mlogger.log("Everything was specified or --terminal was set, "
			"hence the GUI will not be called.", logging.INFO, u"Arguments")

	sets.mlogger.log("Trezor label: %s" % trezor.features.label,
		logging.INFO, "Trezor IO")
	sets.mlogger.log("For each operation click 'Confirm' on Trezor "
		"to give permission.", logging.INFO, "Trezor IO")

	fileMap = FileMap(trezor, sets)

	if ((sets.PArg is None) or (len(sets.inputFiles) <= 0)) and (not sets.TArg):
		# something was not specified, so we call the GUI
		# or user wants GUI, so we call the GUI
		dialog.setFileMap(fileMap)
		dialog.setVersion(basics.VERSION_STR)
		showGui(trezor, dialog, sets)
	else:
		useTerminal(fileMap, sets)
	# cleanup
	sets.mlogger.log("Cleaning up before shutting down.", logging.DEBUG, "Info")
	trezor.close()


if __name__ == '__main__':
	main()
