#!/bin/bash

# directory of the test script, i.e. the test directory
DIR=$(dirname "$(readlink -f "$0")")
APP="TrezorSymmetricFileEncryption.py"
PASSPHRASE="test"
OPT=" -t -l 1 -q -p $PASSPHRASE "  # base options
LOG=test.log

green=$(tput setaf 2) # green color
red=$(tput setaf 1) # red color
reset=$(tput sgr0) # revert to normal/default

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
  case "${1,,}" in
    --help | --hel | --he | --h | -help | -h | -v | --v | --version)
  	usage; exit 0 ;;
  esac
fi

# main
if [ $# -ge 1 ]; then
    pushd $DIR > /dev/null
    rm -f $LOG
    for py in $(which python2) $(which python3); do
        echo ""
        echo "Note   : Now performing tests with version $py"
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
        echo "Step  2: Encrypting with: " $py $APP $OPT -e "${plaintextfilearray[@]}"
        $py $APP $OPT -e "${plaintextfilearray[@]}" &>> $LOG
        echo "Step  3: Encrypting filenames with: " $py $APP $OPT -m "${plaintextfilearray[@]}"
        # prints lines like his: Obfuscated filename/path of "LICENSE" is "TQFYqK1nha1IfLy_qBxdGwlGRytelGRJ".
        $py $APP $OPT -m "${plaintextfilearray[@]}" 2>> $LOG | sed -n 's/.*".*".*"\(.*\)".*/\1/p' >  __obfFileNames__.txt
        readarray -t obfuscatedfilearray < __obfFileNames__.txt
        rm __obfFileNames__.txt
        echo "Step  4: Encrypting and obfuscating files with: " $py $APP $OPT -o "${plaintextfilearray[@]}"
        /usr/bin/time -o __time_measurements__.txt -f "%E" -a $py $APP $OPT -o "${plaintextfilearray[@]}" &>> $LOG
        for size in "$@"; do
            mv __${size}.img __${size}.img.org
        done
        echo "Step  5: Decrypting files with: " $py $APP $OPT -d "${encryptedfilearray[@]}"
        $py $APP $OPT -d "${encryptedfilearray[@]}"  &>> $LOG
        echo "Step  6: Comparing original files with en+decrypted files with plaintext filenames"
        for size in "$@"; do
            diff __${size}.img __${size}.img.org
            rm __${size}.img
        done
        echo "Step  7: Decrypting and deobfuscating files with: " $py $APP $OPT -d "${obfuscatedfilearray[@]}"
        /usr/bin/time -o __time_measurements__.txt -f "%E" -a $py $APP $OPT -d "${obfuscatedfilearray[@]}" &>> $LOG
        echo "Step  8: Comparing original files with en+decrypted files with obfuscated filenames"
        for size in "$@"; do
            diff __${size}.img __${size}.img.org
            rm __${size}.img.org
        done
        for obffile in "${obfuscatedfilearray[@]}"; do
            rm -f "$obffile"
        done
        echo "Step  9: Encrypting and obfuscating files with 2-level-encryption: " $py $APP $OPT -o -2 "${plaintextfilearray[@]}"
        /usr/bin/time -o __time_measurements__.txt -f "%E" -a $py $APP $OPT -o -2 "${plaintextfilearray[@]}" &>> $LOG
        for size in "$@"; do
            mv __${size}.img __${size}.img.org
        done
        echo "Step 10: Decrypting and deobfuscating files with 2-level-encryption: " $py $APP $OPT -d "${obfuscatedfilearray[@]}"
        /usr/bin/time -o __time_measurements__.txt -f "%E" -a $py $APP $OPT -d "${obfuscatedfilearray[@]}" &>> $LOG
        echo "Step 11: Comparing original files with en+decrypted files with obfuscated filenames"
        for size in "$@"; do
            diff __${size}.img __${size}.img.org
        done
        echo "Step 12: Encrypting with safety check and wipe: " $py $APP $OPT -e -s -w "${plaintextfilearray[@]}"
        $py $APP $OPT -e -s -w "${plaintextfilearray[@]}" &>> $LOG
        for size in "$@"; do
            ls __${size}.img 2> /dev/null # file should not exist
        done
        echo "Step 13: Decrypting with safety check and wipe: " $py $APP $OPT -d -s -w "${encryptedfilearray[@]}"
        $py $APP $OPT -d -s -w "${encryptedfilearray[@]}" &>> $LOG
        for size in "$@"; do
            ls __${size}.img.tsfe 2> /dev/null # file should not exist
            diff __${size}.img __${size}.img.org
        done
        echo "Step 14: Encrypting with obfuscation, safety check and wipe: " $py $APP $OPT -e -o -s -w "${plaintextfilearray[@]}"
        $py $APP $OPT -e -o -s -w "${plaintextfilearray[@]}" &>> $LOG
        for size in "$@"; do
            ls __${size}.img 2> /dev/null # file should not exist
        done
        echo "Step 15: Decrypting with safety check and wipe: " $py $APP $OPT -d -w "${obfuscatedfilearray[@]}"
        $py $APP $OPT -d -s -w "${obfuscatedfilearray[@]}" &>> $LOG
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
    done
    echo
    echo "Log file contain " $(grep -i error *$LOG | wc -l) " errors."
    echo "Log file contain " $(grep -i critical *$LOG | wc -l) " critical issues."
    echo "Log file contain " $(grep -i warning *$LOG | grep -v noconfirm | grep -v "The option \`--wipe\` is set" | grep -v "exists and encryption will overwrite it" | wc -l) " warnings."
    echo "Log file contain " $(grep -i ascii *$LOG | wc -l) " ascii-vs-unicode issues."
    echo "Log file contain " $(grep -i unicode *$LOG | wc -l) " unicode issues."
    echo "Log file contain " $(grep -i latin *$LOG | wc -l) " latin-vs-unicode issues."
    echo "Log file contain " $(grep -i byte *$LOG | grep -v " from file " | grep -v " to file " | wc -l) " byte-vs-unicode issues."
    popd > /dev/null
else
    # zero arguments, we run preset default test cases
    echo "Note   : This default test will take about 3-10 minutes."
    echo "Note   : If you have a PIN set, you will have to possibly enter it several times. Consider disabling it."
    echo "Note   : Be aware that you will have to press the 'Confirm' button on the Trezor many times."
    ${0} 1K 10K 100K 1M
fi
exit 0
