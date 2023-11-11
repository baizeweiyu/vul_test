/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"
#define NewCipher(klass) \
    TypedData_Wrap_Struct((klass), &ossl_cipher_type, 0)
#define AllocCipher(obj, ctx) do { \
    (ctx) = EVP_CIPHER_CTX_new(); \
    if (!(ctx)) \
	ossl_raise(rb_eRuntimeError, NULL); \
    RTYPEDDATA_DATA(obj) = (ctx); \
} while (0)
#define GetCipherInit(obj, ctx) do { \
    TypedData_Get_Struct((obj), EVP_CIPHER_CTX, &ossl_cipher_type, (ctx)); \
} while (0)
#define GetCipher(obj, ctx) do { \
    GetCipherInit((obj), (ctx)); \
    if (!(ctx)) { \
	ossl_raise(rb_eRuntimeError, "Cipher not inititalized!"); \
    } \
} while (0)
#define SafeGetCipher(obj, ctx) do { \
    OSSL_Check_Kind((obj), cCipher); \
    GetCipher((obj), (ctx)); \
} while (0)
/*
 * Classes
 */
VALUE cCipher;
VALUE eCipherError;
static ID id_auth_tag_len;

static VALUE ossl_cipher_alloc(VALUE klass);
static void ossl_cipher_free(void *ptr);

    
          
            
    

          
          Expand Down
          
            
    

          
          Expand Up
    
    @@ -118,7 +118,6 @@ ossl_cipher_initialize(VALUE self, VALUE str)
  
static const rb_data_type_t ossl_cipher_type = {
    "OpenSSL/Cipher",
    {
	0, ossl_cipher_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};
/*
 * PUBLIC
 */
const EVP_CIPHER *
GetCipherPtr(VALUE obj)
{
    if (rb_obj_is_kind_of(obj, cCipher)) {
	EVP_CIPHER_CTX *ctx;
	GetCipher(obj, ctx);
	return EVP_CIPHER_CTX_cipher(ctx);
    }
    else {
	const EVP_CIPHER *cipher;
	StringValueCStr(obj);
	cipher = EVP_get_cipherbyname(RSTRING_PTR(obj));
	if (!cipher)
	    ossl_raise(rb_eArgError,
		       "unsupported cipher algorithm: %"PRIsVALUE, obj);
	return cipher;
    }
}
VALUE
ossl_cipher_new(const EVP_CIPHER *cipher)
{
    VALUE ret;
    EVP_CIPHER_CTX *ctx;
    ret = ossl_cipher_alloc(cCipher);
    AllocCipher(ret, ctx);
    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, -1) != 1)
	ossl_raise(eCipherError, NULL);
    return ret;
}
/*
 * PRIVATE
 */
static void
ossl_cipher_free(void *ptr)
{
    EVP_CIPHER_CTX_free(ptr);
}
static VALUE
ossl_cipher_alloc(VALUE klass)
{
    return NewCipher(klass);
}
/*
 *  call-seq:
 *     Cipher.new(string) -> cipher
 *
 *  The string must contain a valid cipher name like "AES-128-CBC" or "3DES".
 *
 *  A list of cipher names is available by calling OpenSSL::Cipher.ciphers.
 */
static VALUE
ossl_cipher_initialize(VALUE self, VALUE str)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    char *name;
    unsigned char dummy_key[EVP_MAX_KEY_LENGTH] = { 0 };
    name = StringValueCStr(str);
    GetCipherInit(self, ctx);
    if (ctx) {
    	ossl_raise(rb_eRuntimeError, "Cipher already inititalized!");
    }
    AllocCipher(self, ctx);
    if (!(cipher = EVP_get_cipherbyname(name))) {
	    ossl_raise(rb_eRuntimeError, "unsupported cipher algorithm (%"PRIsVALUE")", str);
    }
    /*
     * EVP_CipherInit_ex() allows to specify NULL to key and IV, however some
     * ciphers don't handle well (OpenSSL's bug). [Bug #2768]
     *
     * The EVP which has EVP_CIPH_RAND_KEY flag (such as DES3) allows
     * uninitialized key, but other EVPs (such as AES) does not allow it.
     * Calling EVP_CipherUpdate() without initializing key causes SEGV so we
     * set the data filled with "\0" as the key by default.
     */
    if (EVP_CipherInit_ex(ctx, cipher, NULL, dummy_key, NULL, -1) != 1)
	      ossl_raise(eCipherError, NULL);

    return self;
}
