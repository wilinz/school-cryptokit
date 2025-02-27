#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


char *ffi_decrypt_aes_128_cbc_64prefix(const char *encrypted, const char *key);

char *ffi_encrypt_aes_128_cbc_64prefix(const char *plain, const char *key);

void ffi_free_c_string(char *s);

char *ffi_get_decrypt_host(const char *ciphertext);

char *ffi_get_encrypt_host(const char *plaintext);

char *ffi_get_ordinary_url(const char *url);

char *ffi_get_vpn_url(const char *url);

void ffi_set_vpn_host(const char *host);
