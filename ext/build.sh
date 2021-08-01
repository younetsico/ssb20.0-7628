#!/bin/sh
## Run this script to build the php_secureblackbox extension in UNIX systems (Linux, Mac OS, etc..).
#

phpize
aclocal
./configure --enable-SecureBlackbox
make install
