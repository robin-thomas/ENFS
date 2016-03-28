
/*
 * ENFS v1.0
 * https://github.com/robin-thomas/ENFS
 * Copyright 2015 Robin Thomas.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _RSA_H
#define _RSA_H

#include <string>
#include <openssl/rsa.h>

#define KEY_FILE "key.pem"
#define CERT_FILE "cert.pem"

#define BUF_SIZE 4096
#define RSA_KEY_SIZE 2048
#define EXP RSA_F4

void
printHex (const char * title,
          const unsigned char * s,
          int len);

void
initOpenSSL (void);

void
cleanup_openssl (void);

void
handle_openssl_error (void);

int
genRSAKeys (const std::string & path);

RSA *
createRSA (const std::string & path,
           bool p,
           bool publ);

int
public_encrypt (const std::string & path,
                bool p,
                unsigned char * data,
                int len,
                unsigned char * encrypted);

int
private_decrypt (const std::string & path,
                 bool p,
                 unsigned char * data,
                 int len,
                 unsigned char * decrypted);

bool
verifyCert (const char * cert);

EVP_PKEY *
generate_key (void);

X509 *
generate_x509 (EVP_PKEY * pkey);

bool
write_to_disk (EVP_PKEY * pkey,
               X509 * x509,
               const std::string & path,
               const std::string & pass = std::string());

bool
loadCert (SSL_CTX * ctx,
          const std::string & certFile,
          const std::string & keyFile);

SSL_CTX *
init (void);

#endif
