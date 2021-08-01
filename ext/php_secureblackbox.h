
#ifndef PHP_SECUREBLACKBOX_H
#define PHP_SECUREBLACKBOX_H

extern zend_module_entry secureblackbox_module_entry;
#define phpext_secureblackbox_ptr &secureblackbox_module_entry

#ifdef PHP_WIN32
#define PHP_SECUREBLACKBOX_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#define PHP_SECUREBLACKBOX_API __attribute__ ((visibility("default")))
#else
#define PHP_SECUREBLACKBOX_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(secureblackbox);
PHP_MSHUTDOWN_FUNCTION(secureblackbox);
PHP_MINFO_FUNCTION(secureblackbox);

#ifdef ZTS
#define SECUREBLACKBOX_G(v) TSRMG(secureblackbox_globals_id, zend_secureblackbox_globals *, v)
#else
#define SECUREBLACKBOX_G(v) (secureblackbox_globals.v)
#endif

#endif	/* PHP_SECUREBLACKBOX_H */
