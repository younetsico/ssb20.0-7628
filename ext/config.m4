PHP_ARG_ENABLE(SecureBlackbox, whether to enable SecureBlackbox support,
[  --enable-SecureBlackbox        Enable SecureBlackbox support])

OSTYPE="$(uname -s)"

if (test "$OSTYPE" == "Darwin") || (test "$OSTYPE" == "darwin") || (test "$OSTYPE" == "macos"); then
OSFLAGS="-D MACOS"
LIB_DIR="$(pwd)/lib"
LIB_NAME="secureblackbox.20.0"
else
  # checking php 32/64 bit
  if (test `php -r 'echo PHP_INT_SIZE;'` == 8); then
    LIB_DIR="$(pwd)/lib/x64"
  else
    LIB_DIR="$(pwd)/lib/x86"
  fi

  LIB_NAME="secureblackbox"
  AC_CONFIG_COMMANDS_POST([ln -s $LIB_DIR/libsecureblackbox.so.20.0 $LIB_DIR/libsecureblackbox.so.20 & ln -s $LIB_DIR/libsecureblackbox.so.20.0 $LIB_DIR/libsecureblackbox.so])
fi

if test "$PHP_SecureBlackbox" != "no"; then 

dnl # --with-SecureBlackbox -> check for lib and symbol presence
  PHP_REQUIRE_CXX()
  PHP_ADD_LIBRARY(stdc++, 1, SECUREBLACKBOX_SHARED_LIBADD)
  PHP_ADD_LIBRARY_WITH_PATH($LIB_NAME, $LIB_DIR, SECUREBLACKBOX_SHARED_LIBADD)

  PHP_NEW_EXTENSION(secureblackbox, php_secureblackbox.c, $ext_shared,  , $OSFLAGS)
  PHP_SUBST(SECUREBLACKBOX_SHARED_LIBADD)

fi