
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

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "rsa.h"


// Function to print the HEX value of an unsigned char string
void
printHex (const char * title,
          const unsigned char * s,
          int len)
{
  printf("%s:", title);
  for (int i = 0; i < len; i++) {
    if ((i % 16) == 0) {
      printf("\n%04x", i);
    }
    printf(" %02x", s[i]);
  }
  printf("\n");
}


// Function to load all the SSL libraries
void
initOpenSSL (void)
{
  if (SSL_library_init()) {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", RSA_KEY_SIZE);
  } else {
    exit(EXIT_FAILURE);
  }
}


// Function to cleanup SSL after use
void
cleanup_openssl (void)
{
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  ERR_remove_thread_state(0);
  EVP_cleanup();
}


// Function to display SSL errors
void
handle_openssl_error (void)
{
  ERR_print_errors_fp(stderr);
}


// Generate RSA key
EVP_PKEY *
generate_key (void)
{

  EVP_PKEY * pkey = EVP_PKEY_new();
  if (!pkey) {
    fprintf(stderr, "Unable to create EVP_PKEY structure");
    return NULL;
  }

  RSA * rsa = RSA_generate_key(RSA_KEY_SIZE, EXP, NULL, NULL);

  if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
    fprintf(stderr, "Unable to generate %d-bit RSA key", RSA_KEY_SIZE);
    EVP_PKEY_free(pkey);
    return NULL;
  }

  return pkey;
}


// Generate a self-signed x509 certificate
X509 *
generate_x509 (EVP_PKEY * pkey)
{
  X509 * x509 = X509_new();
  if (!x509) {
    fprintf(stderr, "Unable to create X509 structure");
    return NULL;
  }

  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
  X509_set_pubkey(x509, pkey);
  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"IN", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"Robin Thomas", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x509, name);

  if (!X509_sign(x509, pkey, EVP_sha1())) {
    fprintf(stderr, "Error in signing certificate");
    X509_free(x509);
    return NULL;
  }

  return x509;
} 


// Write the private key and certificate to disk
bool
write_to_disk (EVP_PKEY * pkey,
               X509 * x509,
               const std::string & path,
               const std::string & pass)
{
  
  int ret;
  FILE * f = NULL;
  std::string fpath;

  fpath = path + "/" + KEY_FILE;
  f = fopen(fpath.c_str(), "wb");
  if (!f) {
    fprintf(stderr, "Unable to open \"%s\" for writing\n", KEY_FILE);
    return false;
  }

  if (pass.empty()) {
     ret = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
  } else {
     ret = PEM_write_PrivateKey(f, pkey, EVP_aes_256_cbc(), (unsigned char*)pass.c_str(), pass.size(), NULL, NULL);
  }
  fclose(f);

  if (!ret) {
    fprintf(stderr, "Unable to write private key to disk\n");
    return false;
  }

  fpath = path + "/" + CERT_FILE;
  f = fopen(fpath.c_str(), "wb");
  if (!f) {
    fprintf(stderr, "Unable to open \"%s\" for writing\n", CERT_FILE);
    return false;
  }

  ret = PEM_write_X509(f, x509);
  fclose(f);

  if (!ret) {
    fprintf(stderr, "Unable to write certificate to disk\n");
    return false;
  }
  return true;
} 


// Load the private key and certificate
bool
loadCert (SSL_CTX * ctx,
          const std::string & certFile,
          const std::string & keyFile) 
{
  if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Unable to load certificate file\n");
    return false;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Unable to load private key\n");
    return false;
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "Private key does not match certificate\n");
    return false;
  }

  return true;
}


// Initiliaze SSL connection
SSL_CTX *
init (void)
{
  if (SSL_library_init()) {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    RAND_load_file("/dev/urandom", RSA_KEY_SIZE);

    const SSL_METHOD* method = SSLv23_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    return ctx;
  } else {
    exit(EXIT_FAILURE);
  }
}
