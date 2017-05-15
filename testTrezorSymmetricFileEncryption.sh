#!/bin/bash

passphrase="test"

# outputs to stdout the --help usage message.
usage () {
  echo "${0##*/}: Usage: ${0##*/} [--help] <size> ..."
  echo "${0##*/}: e.g. ${0##*/} 1K"
  echo "${0##*/}: e.g. ${0##*/} 10K"
  echo "${0##*/}: e.g. ${0##*/} 1M"
  echo "${0##*/}: e.g. ${0##*/} 1K 2K 3K"
  echo "${0##*/}: Tests larger than 1M will take minutes (0.8M/min)."
}

if [ $# -eq 1 ]; then
  case "$1" in
    --help | --hel | --he | --h | -help | -h | -v | --version)
  	usage; exit 0 ;;
  esac
fi

if [ $# -ge 1 ]; then
    set -- "$@"
    plaintextfilearray=()
    encryptedfilearray=()
    rm -f __time_measurements__.txt
    echo "Note   : Watch your Trezor device, click \"Confirm\" button on Trezor when required."
    echo "Step  1: Preparing all test files"
    for size in "$@"; do
        rm __${size}.img*  &> /dev/null
        fallocate -l ${size} __${size}.x.img
        dd if=/dev/random  of=__${size}.random.bin bs=32b count=1 &> /dev/null
        echo "This is a test." > __${size}.test.txt
        cat __${size}.test.txt __${size}.random.bin __${size}.x.img __${size}.random.bin __${size}.test.txt > __${size}.img
        rm __${size}.test.txt __${size}.random.bin __${size}.x.img
        plaintextfilearray+=("__${size}.img")
        encryptedfilearray+=("__${size}.img.tsfe")
    done
    echo "Step  2: Encrypting with: " ./TrezorSymmetricFileEncryption.py -t  -e "${plaintextfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -e -p ${passphrase} "${plaintextfilearray[@]}" &> /dev/null
    echo "Step  3: Encrypting filenames with: " ./TrezorSymmetricFileEncryption.py -t  -m "${plaintextfilearray[@]}"
    # prints lines like his: Obfuscated filename/path of "LICENSE" is "TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ".
    ./TrezorSymmetricFileEncryption.py -t  -m -p ${passphrase} "${plaintextfilearray[@]}" 2> /dev/null | sed -n 's/.*".*".*"\(.*\)".*/\1/p' >  __obfFileNames__.txt
    readarray -t obfuscatedfilearray < __obfFileNames__.txt
    rm __obfFileNames__.txt
    echo "Step  4: Encrypting and obfuscating files with: " ./TrezorSymmetricFileEncryption.py -t  -o "${plaintextfilearray[@]}"
    /usr/bin/time -o __time_measurements__.txt -f "%E" -a ./TrezorSymmetricFileEncryption.py -t  -o -p ${passphrase} "${plaintextfilearray[@]}" &> /dev/null
    for size in "$@"; do
        mv __${size}.img __${size}.img.org
    done
    echo "Step  5: Decrypting files with: " ./TrezorSymmetricFileEncryption.py -t  -d "${encryptedfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -d -p ${passphrase} "${encryptedfilearray[@]}"  &> /dev/null
    echo "Step  6: Comparing original files with en+decrypted files with plaintext filenames"
    for size in "$@"; do
        diff __${size}.img __${size}.img.org
        rm __${size}.img
    done
    echo "Step  7: Decrypting and deobfuscating files with: " ./TrezorSymmetricFileEncryption.py -t  -d "${obfuscatedfilearray[@]}"
    /usr/bin/time -o __time_measurements__.txt -f "%E" -a ./TrezorSymmetricFileEncryption.py -t  -d -p ${passphrase} "${obfuscatedfilearray[@]}" &> /dev/null
    echo "Step  8: Comparing original files with en+decrypted files with obfuscated filenames"
    for size in "$@"; do
        diff __${size}.img __${size}.img.org
        rm __${size}.img.org
    done
    for obffile in "${obfuscatedfilearray[@]}"; do
        rm -f "$obffile"
    done
    echo "Step  9: Encrypting and obfuscating files with 2-level-encryption: " ./TrezorSymmetricFileEncryption.py -t  -o -2 "${plaintextfilearray[@]}"
    /usr/bin/time -o __time_measurements__.txt -f "%E" -a ./TrezorSymmetricFileEncryption.py -t  -o -2 -p ${passphrase} "${plaintextfilearray[@]}" &> /dev/null
    for size in "$@"; do
        mv __${size}.img __${size}.img.org
    done
    echo "Step 10: Decrypting and deobfuscating files with 2-level-encryption: " ./TrezorSymmetricFileEncryption.py -t  -d "${obfuscatedfilearray[@]}"
    /usr/bin/time -o __time_measurements__.txt -f "%E" -a ./TrezorSymmetricFileEncryption.py -t  -d -p ${passphrase} "${obfuscatedfilearray[@]}" &> /dev/null
    echo "Step 11: Comparing original files with en+decrypted files with obfuscated filenames"
    for size in "$@"; do
        diff __${size}.img __${size}.img.org
        rm __${size}.img
    done
    echo "Step 11: Encrypting with safety check and wipe: " ./TrezorSymmetricFileEncryption.py -t  -e -s -w -p ${passphrase} "${plaintextfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -e -s -w -p ${passphrase} "${plaintextfilearray[@]}" &> /dev/null
    for size in "$@"; do
        ls __${size}.img 2> /dev/null # file should not exist
    done
    echo "Step 12: Decrypting with wipe: " ./TrezorSymmetricFileEncryption.py -t  -d -w -p ${passphrase} "${encryptedfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -d -w -p ${passphrase} "${encryptedfilearray[@]}" &> /dev/null
    for size in "$@"; do
        ls __${size}.img.tsfe 2> /dev/null # file should not exist
        diff __${size}.img __${size}.img.org
    done
    echo "Step 13: Encrypting with obfuscation, safety check and wipe: " ./TrezorSymmetricFileEncryption.py -t  -e -o -s -w -p ${passphrase} "${plaintextfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -e -o -s -w -p ${passphrase} "${plaintextfilearray[@]}" &> /dev/null
    for size in "$@"; do
        ls __${size}.img 2> /dev/null # file should not exist
    done
    echo "Step 14: Decrypting with wipe: " ./TrezorSymmetricFileEncryption.py -t  -d -w -p ${passphrase} "${obfuscatedfilearray[@]}"
    ./TrezorSymmetricFileEncryption.py -t  -d -w -p ${passphrase} "${obfuscatedfilearray[@]}" &> /dev/null
    for size in "$@"; do
        diff __${size}.img __${size}.img.org
    done
    for obffile in "${obfuscatedfilearray[@]}"; do
        ls "$obffile"  2> /dev/null # file should not exist
    done
    for size in "$@"; do
        rm -f __${size}.img
        rm -f __${size}.img.org
        rm -f __${size}.img.tsfe
    done
    for obffile in "${obfuscatedfilearray[@]}"; do
        rm -f "$obffile"
    done
    echo "End    : If no warnings or errors were echoed, then there were no errors, all tests terminated successfully."
else
    # zero arguments, we run preset default test cases
    echo "Note   : This default test will take about 3-4 minutes."
    echo "Note   : If you have a PIN set, you will have to enter it about 10 times. Consider disabling it."
    ${0} 1K 10K 100K 1M
fi
