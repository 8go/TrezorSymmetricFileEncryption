from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import logging
from encoding import unpack

"""
This file contains some constant variables like version numbers,
default values, etc.
"""

# Name of application
NAME = u'TrezorSymmetricFileEncryption'

# Name of software version, must be less than 16 bytes long
VERSION_STR = u'v0.6.2'

# Date of software version, only used in GUI
VERSION_DATE_STR = u'June 2017'

# default log level
DEFAULT_LOG_LEVEL = logging.INFO  # CRITICAL, ERROR, WARNING, INFO, DEBUG

# short acronym used for name of logger
LOGGER_ACRONYM = u'tsfe'

# location of logo image
LOGO_IMAGE = u'icons/TrezorSymmetricFileEncryption.216x100.svg'

# file extension for encrypted files with plaintext filename
FILEEXT = u'.tsfe'

# Data storage version, format of TSFE file
FILEFORMAT_VERSION = 1


class Magic(object):
	"""
	Few magic constant definitions so that we know which nodes to search
	for keys.
	"""

	headerStr = b'TSFE'
	hdr = unpack("!I", headerStr)

	# first level encryption
	# unlock key for first level AES encryption, key from Trezor, en/decryption on PC
	levelOneNode = [hdr, unpack("!I", b'DEC1')]
	levelOneKey = "Decrypt file for first time?"  # string to derive wrapping key from

	# second level encryption
	# second level AES encryption, de/encryption on trezor device
	levelTwoNode = [hdr, unpack("!I", b'DEC2')]
	levelTwoKey = "Decrypt file for second time?"

	# only used for filename encryption (no confirm button click desired)
	fileNameNode = [hdr, unpack("!I", b'FLNM')]  # filename encryption for filename obfuscation
	fileNameKey = "Decrypt filename only?"
