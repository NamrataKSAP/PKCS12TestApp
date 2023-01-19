//
//  OpenSSLHelper.c
//  Utils
//
//  Copyright © 2018 SAP SE or an SAP affiliate company. All rights reserved.
//
//  No part of this publication may be reproduced or transmitted in any form or for any purpose
//  without the express permission of SAP SE. The information contained herein may be changed
//  without prior notice.
//

#include "OpenSSLHelper.h"
#include "string.h"
#include "openssl/err.h"
#include "openssl/pkcs12.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pem.h"
#include "openssl/provider.h"


// MARK: - Private

void initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    
//    OSSL_PROVIDER_try_load(NULL, "legacy", 1);
//    OSSL_PROVIDER_try_load(NULL, "default", 1);
}

BIO* createPKCS12fromPKCS12(const unsigned char* data, long dataLength, char* originalPassphrase, char* newPassphrase) {

    OSSL_PROVIDER *legacy = OSSL_PROVIDER_try_load(NULL, "legacy", 1);
    OSSL_PROVIDER *defaultProvider = OSSL_PROVIDER_try_load(NULL, "default", 1);
    int nid_key = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
    int nid_cert = NID_pbe_WithSHA1And40BitRC2_CBC;
    
    BIO* bp = BIO_new_mem_buf(data, (int)dataLength);
    PKCS12* originalPKCS12 = NULL;
    d2i_PKCS12_bio(bp, &originalPKCS12);
    BIO_free(bp);

    EVP_PKEY* privateKey;
    X509* x509;
    STACK_OF(X509)* caChain = NULL;
    PKCS12_parse(originalPKCS12, originalPassphrase, &privateKey, &x509, &caChain);
    PKCS12_free(originalPKCS12);
    
//    printf("%d", nid_key);
//    printf("%d", nid_cert);
    
    PKCS12* newPKCS12 = PKCS12_create(newPassphrase, "SAP Identity", privateKey, x509, caChain, nid_key, nid_cert, 0, PKCS12_DEFAULT_ITER, 0);
    unsigned long a = ERR_get_error();
    printf("%lu", a);
    EVP_PKEY_free(privateKey);
    X509_free(x509);
    sk_X509_free(caChain);
    BIO* mem = NULL;
    int verify = PKCS12_verify_mac(newPKCS12, newPassphrase, 0);
    printf("%d", verify);
    
    if (newPKCS12 != NULL) {
        mem = BIO_new(BIO_s_mem());
        i2d_PKCS12_bio(mem, newPKCS12);
        PKCS12_free(newPKCS12);
        
    }
    
    return mem;
}

