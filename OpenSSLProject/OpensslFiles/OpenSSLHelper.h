//
//  OpenSSLHelper.h
//  Utils
//
//  Copyright © 2018 SAP SE or an SAP affiliate company. All rights reserved.
//
//  No part of this publication may be reproduced or transmitted in any form or for any purpose
//  without the express permission of SAP SE. The information contained herein may be changed
//  without prior notice.
//

#ifndef OpenSSLHelper_h
#define OpenSSLHelper_h

#include "openssl/bio.h"

void initializeOpenSSL(void);
BIO* createPKCS12fromPKCS12(const unsigned char* data, long dataLength, char* originalPassphrase, char* newPassphrase);

#endif /* OpenSSLHelper_h */
