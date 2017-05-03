#!/bin/bash

# outputs to stdout the --help usage message.
usage () {
  echo "${0##*/}: Usage: ${0##*/} [--help] <size>"
  echo "${0##*/}: e.g. ${0##*/} 1K"
  echo "${0##*/}: e.g. ${0##*/} 1M"
  echo "${0##*/}: e.g. ${0##*/} 1G"
  echo "${0##*/}: e.g. ${0##*/} 2047M  # this is the maximum size as it is currently limited to 2G minus a few bytes"
}

if [ $# -eq 0 ] || [ $# -lt 1 ]; then usage; exit 0; fi

if [ $# -eq 1 ]; then
  case "$1" in
    --help | --hel | --he | --h | -help | -h | -v)
  	usage; exit 0 ;;
  esac
fi

size=$1

rm __${size}.img*  &> /dev/null
fallocate -l ${size} __${size}.x.img
dd if=/dev/random  of=__${size}.random.bin bs=32b count=1 &> /dev/null
echo "This is a test." > __${size}.test.txt
cat __${size}.test.txt __${size}.random.bin __${size}.x.img __${size}.random.bin __${size}.test.txt > __${size}.img
rm __${size}.test.txt __${size}.random.bin __${size}.x.img
./TrezorSymmetricFileEncryption.py -t  __${size}.img   &> /dev/null
mv __${size}.img __${size}.img.org
./TrezorSymmetricFileEncryption.py -t  __${size}.img.tsfe   &> /dev/null
diff __${size}.img __${size}.img.org
rm __${size}.img*

echo "If nothing was echoed, then there were no errors, all tests terminated successfully."
