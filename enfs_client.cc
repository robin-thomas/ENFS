
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

#include <unistd.h>
#include <pwd.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include "rsa.h"
#include "client_fs.h"


// Display the options for ENFS file system
void usage() {
  fprintf(stdout, "\n[Usage]: enfs -option [value]\n\n");
  fprintf(stdout, " -h                      Display this help page\n");
  fprintf(stdout, " -m [mountpoint] [host]  Mount   ENFS file system\n");
  fprintf(stdout, " -u [mountpoint]         Unmount ENFS file system\n\n");
}


// Iniitliaze the 256-bit AES key
// This is key is used for encrypting/decrypting the data
// stored in files in the server
bool
loadAESKey (const std::string & path)
{

  FILE * fp = NULL;
  std::string fpath;
  unsigned char key[AES_KEY_SIZE];

  fpath = path + "/" + AES_KEY_FILE;
  if ((fp = fopen(fpath.c_str(), "rb")) == NULL) {
    fprintf(stderr, "Unable to open AES key file!");
    return false;
  }

  fread(key, AES_KEY_SIZE, 1, fp);
  fclose(fp);

  if (AES_set_encrypt_key(key, AES_KEY_SIZE, &enc_key) < 0) {
    return false;
  }

  if (AES_set_decrypt_key(key, AES_KEY_SIZE, &dec_key) < 0) {
    return false;
  }

  printf("AES key loaded successfuly\n");

  return true;
}


// Generate the 256-bit AES key
// This is the key used for encrypting/decrypting the data
// stored in files in the server
bool
genAESKey (const std::string & path)
{

  FILE * fp = NULL;
  std::string fpath;
  unsigned char key[AES_KEY_SIZE];

  fpath = path + "/" + AES_KEY_FILE;
  if ((fp = fopen(fpath.c_str(), "wb")) == NULL) {
    fprintf(stderr, "Unable to open AES key file\n");
    return false;
  }

  if (!RAND_bytes(key, AES_KEY_SIZE)) {
    fprintf(stderr, "Unable to generate AES key\n");
    return false;
  }

  fwrite(key, AES_KEY_SIZE, 1, fp);
  fclose(fp);

  printf("AES key generated successfully\n");

  return loadAESKey(path);
}


// Get a random 10-character code from the server
// Client should send it to the server for every file system call.
// This code is used to uniquely identify the client
bool
getCodeFromServer (const std::string & serv,
                   const std::string & path)
{

  // Initialize the client for SSL
  printf("Initializing client...\n");
  SSL_CTX* ctx = init();
  if (ctx == NULL) {
    fprintf(stderr, "Unable to initialize client\n");
    return false;
  }

  // Load the private key and X509 certificate
  SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
  printf("Loading certificates...\n");
  if (loadCert(ctx, path + "/" + CERT_FILE, path + "/" + KEY_FILE) == false) {
    return false;
  }
  printf("Certificate loaded\n");

  int server = connServer(serv, SERVER_PORT);
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);

  printf("Trying to connect to server...\n");
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return false;
  }
  printf("Connected to server\n");

  std::string msg = "1";
  SSL_write(ssl, msg.c_str(), msg.size());
  char buf[BUF_SIZE];
  int bytes = SSL_read(ssl, buf, sizeof buf);
  buf[bytes] = 0;
  printf("Received: \"%s\"\n", buf);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  std::string npath = path + "/code";
  int fd = open(npath.c_str(), O_CREAT | O_WRONLY, S_IRWXU);
  if (fd < 0) {
    fprintf(stderr, "Unable to create file\n");
    return false;
  }
  write(fd, buf, bytes);
  close(fd);
  printf("Saved code to disk\n");

  return true;
}


// Generate the private key and certificate
// and get the code from server
bool
genKeyAndCert (const std::string & path,
               const std::string & server)
{

  printf("Generating RSA keys...\n");
  printf("Set the password [26 chars]: ");
  scanf("%s", upass);
  EVP_PKEY* pkey = generate_key();
  if (!pkey) {
    return false;
  }
  printf("RSA %d-keys generated\n", RSA_KEY_SIZE);

  printf("Generating X509 certificate...\n");
  X509* x509 = generate_x509(pkey);
  if (!x509) {
    return false;
  }
  printf("X509 certificate generated\n");

  printf("Writing key and certificate to disk\n");
  bool ret = write_to_disk(pkey, x509, path, upass);
  EVP_PKEY_free(pkey);
  X509_free(x509);

  if (ret) {
    return genAESKey(path) && getCodeFromServer(server, path);
  } else {
    return false;
  }
}


// Auhenticate with the server
// SSL authentication handled internally
bool
authClientServer (SSL_CTX * ctx,
                  const std::string & path,
                  const std::string & serv)
{
  // Connect to the server
  printf("Trying to connect to server...\n");
  int server = connServer(serv, SERVER_PORT);
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return false;
  }
  printf("Connected to server\n");

  // Authentication
  std::string msg = "2";
  std::string code = path + "/code";
  FILE* fp = fopen(code.c_str(), "r");
  if (fp == NULL) {
    fprintf(stderr, "Unable to open client code file\n");
    return false;
  }
  char buf[BUF_SIZE];
  memset(buf, 0, BUF_SIZE);
  fgets(buf, BUF_SIZE, fp);
  buf[strlen(buf)] = '\0';
  msg += buf;
  SSL_write(ssl, msg.c_str(), msg.size());
  char cde[BUF_SIZE];
  memset(cde, 0, BUF_SIZE);
  int bytes = SSL_read(ssl, cde, sizeof cde);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);
  cde[bytes] = 0;
  if (strcmp(cde, buf) == 0) {
    printf("Authenticated\n");
    return true;
  }

  return false;
}


// Load the client certificate and private key
// and authenticate with the server
bool
loadKeyAndCert (const std::string & path,
                const std::string & serv)
{  
  // Initialize the client for SSL
  printf("Initializing client...\n");
  SSL_CTX* ctx = init();
  if (ctx == NULL) {
    fprintf(stderr, "Unable to initialize server\n");
    return false;
  }

  // Load the private key and X509 certificate
  printf("Loading certificates...\n");
  printf("Enter the password [26 chars]: ");
  scanf("%s", upass);
  SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
  if (loadCert(ctx, path + "/" + CERT_FILE, path + "/" + KEY_FILE) == false) {
    return false;
  }
  printf("Certificate loaded\n");

  return loadAESKey(path) && authClientServer(ctx, path, serv);
}


// Main function
int
main (int argc,
      char ** argv)
{
  try {
    // Since ENFS does no access checking, running it as root creates holes in system security.
    // So if root tries to mount ENFS, ENFS refuse to mount
    if ((getuid() == 0) || (geteuid() == 0)) {
      throw "Cannot run ENFS as root";
    }

    // Check for valid user input
    if (argc == 1) {
      usage();
      return 1;
    }

    // Initialize the OpenSSL libraries
    initOpenSSL();

    switch (argv[1][1]) {

      // Display the ENFS options
      case 'h': {
        usage();
        break;
      }

      // Mount the ENFS file system
      case 'm': {
        // Invalid ENFS mount options
        if (argc < 4) {
          usage();
        } else {
          // Check whether ENFS file system is already mounted
          FILE* fp = popen("cat /etc/mtab | grep enfs | wc -c", "r");
          if (fgetc(fp) == '0') {
            // Create ENFS directory to store config and log files
            const char* homeDir = getenv("XDG_CONFIG_HOME");
            if (homeDir == NULL || (homeDir = getenv("HOME")) == NULL) {
              homeDir = getpwuid(getuid())->pw_dir;
            }
            std::string path = std::string(homeDir) + "/.enfs";
            int stat = mkdir(path.c_str(), S_IRWXU | S_IRGRP | S_IROTH);
            if (stat != 0 && !(stat == -1 && errno == EEXIST)) {
              throw "Unable to create ENFS configuration directory";
            }

            // Mounting for the first time
            if (stat == 0) {
              if (!genKeyAndCert(path, argv[argc - 1])) {
                throw "Unable to initialize client!";
              }
            } else if (!loadKeyAndCert(path, argv[argc - 1])) {
              throw "Unable to authenticate ENFS server!";
            }
            std::string host = argv[argc-- - 1];
            for (int i = 0; i < argc - 1; i++) {
              argv[i] = argv[i + 1];
            }
            argc--;
            if (initENFS(host, path, argc, argv)) {
              throw "Unable to mount ENFS file system";
            }
          } else {
            throw "ENFS file system already mounted!";
          }
        }
        break;
      }

      // Unmount the ENFS file system
      case 'u': {
        // Invalid ENFS unmount options
        if (argc != 3) {
          usage();
        } else {
          std::string str = std::string("fusermount -uz ") + argv[argc - 1] + " 2>&1 | wc -c";
          FILE* fp = popen(str.c_str(), "r");
          if (fgetc(fp) != '0') {
            throw "ENFS file system not mounted";
          }
          fprintf(stdout, "\nENFS unmounted successfully\n");
        }
        break;
      }

      // Invalid ENFS option
      default: {
        usage();
      }
    }
  } catch(const char* err) {
    fprintf(stderr, "\n[ERROR] %s\n\n", err);
  }

  cleanup_openssl();

  return 0;
}
