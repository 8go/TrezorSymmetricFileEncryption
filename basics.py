from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import logging

# file extension for encrypted files with plaintext filename
TSFEFILEEXT = ".tsfe"

# Data storage version, format of TSFE file
TSFEFILEFORMATVERSION = 1

# Name of software version, must be less than 16 long
TSFEVERSION = "v0.5.0"

# Date of software version, only used in GUI
TSFEVERSIONTEXT = "May 2017"

# default log level
LOGGINGLEVEL = logging.INFO  # CRITICAL, ERROR, WARNING, INFO, DEBUG
