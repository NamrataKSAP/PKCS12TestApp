//
//  OpenSSLHelperProxy.m
//  Utils
//
//  Copyright © 2018 SAP SE or an SAP affiliate company. All rights reserved.
//
//  No part of this publication may be reproduced or transmitted in any form or for any purpose
//  without the express permission of SAP SE. The information contained herein may be changed
//  without prior notice.
//

#import <Foundation/Foundation.h>

#include "OpenSSLHelperProxy.h"
#include "OpenSSLHelper.h"
#include "openssl/bio.h"

static OpenSSLHelperProxy* _shared = nil;

@implementation OpenSSLHelperProxy

+(OpenSSLHelperProxy*)shared {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _shared = [[OpenSSLHelperProxy alloc] init];
    });
    return _shared;
}

+(void)setShared:(OpenSSLHelperProxy*)instance {
    _shared = instance;
}

-(id)init {
    self = [super init];
    if (self) {
        initializeOpenSSL();
    }
    return self;
}


-(NSData* _Nullable)createPKCS12fromPKCS12Data:(NSData* _Nonnull)PKCS12Data passphraseOriginal:(NSString* _Nonnull)passphraseOriginal passphraseNew:(NSString* _Nonnull)passphraseNew {
    BIO* mem = createPKCS12fromPKCS12([PKCS12Data bytes], [PKCS12Data length], (char*)[passphraseOriginal UTF8String], (char*)[passphraseNew UTF8String]);
    NSData* data = [OpenSSLHelperProxy NSDataFromBIO:mem];
    return data;
}

+(NSData*)NSDataFromBIO:(BIO*)mem {
    NSData* data = nil;
    if (mem != NULL) {
        char* ptr = NULL;
        
        size_t size = BIO_get_mem_data(mem, &ptr);
        data = [NSData dataWithBytes:ptr length:size];
        BIO_free(mem);
    }
    return data;
}

@end
