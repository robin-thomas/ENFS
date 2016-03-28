
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

#include "client_fs.h"
#include "rsa.h"

#include <sstream>

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>


char upass[26];
AES_KEY enc_key, dec_key;


int pem_passwd_cb(char *buf, int size, int rwflag, void *pass) {
  memcpy(buf, upass, strlen(upass) + 1);
  return (strlen(buf));
}


int connServer(const std::string& serv, int port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) { 
    fprintf(stderr, "ERROR opening socket");
    return -1;
  }

  struct hostent* server = gethostbyname(serv.c_str());
  if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    return -1;
  }

  struct sockaddr_in serv_addr;
  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
  serv_addr.sin_port = htons(port);

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
    fprintf(stderr, "Unable to connect to %s\n", serv.c_str());
    return -1;
  }
  //fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
  return sockfd;
}


std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  std::stringstream ss(s);
  std::string str;
  while (std::getline(ss, str, delim)) {
    elems.push_back(str);
  }
  return elems;
}


// Function to perform getattr() system call
int enfs_getattr(const char* path, struct stat* statbuf) {
  std::string fpath = path;
  if (fpath.find(".Trash") != std::string::npos || fpath.find("autorun.inf") != std::string::npos || 
      fpath.find(".xdg-volume-info") != std::string::npos || fpath.find("AACS") != std::string::npos ||
      fpath.find("BDSVM") != std::string::npos || fpath.find("BDMV") != std::string::npos) {
    return 0;
  }

  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "31" + ENFS_DATA->code + "&&" + path;
  SSL_write(ssl, msg.c_str(), msg.size());
  char buf[BUF_SIZE];
  int bytes = SSL_read(ssl, buf, sizeof buf);
  buf[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buf);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  std::string reply = buf;
  if (reply[0] == '-') {
    return -ENOENT;
  }

  if (reply.size()) {
    std::vector<std::string> st = split(reply, ':');
    statbuf->st_mode    = std::stoi(st[0]);
    statbuf->st_nlink   = std::stoi(st[1]);
    statbuf->st_uid     = std::stoi(st[2]);
    statbuf->st_gid     = std::stoi(st[3]);
    statbuf->st_size    = std::stoi(st[4]);
    statbuf->st_blksize = std::stoi(st[5]);
    statbuf->st_blocks  = std::stoi(st[6]);
    statbuf->st_atime = std::stol(st[7]);
    statbuf->st_ctime = std::stol(st[8]);
    statbuf->st_mtime = std::stol(st[9]);
  }
  return 0;
}


// Function to create a new directory
int enfs_mkdir(const char *path, mode_t mode) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "32" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(mode);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


// Function to read a directory contents
int enfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "33" + ENFS_DATA->code + "&&" + path;
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  for (std::string i : split(buff, ':')) {
    if (filler(buf, i.c_str(), NULL, 0) != 0) {
      return -ENOMEM;
    }
  }

  return 0;
}


// Function to create a new file
int enfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "34" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(mode);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buf[BUF_SIZE];
  int bytes = SSL_read(ssl, buf, sizeof buf);
  buf[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buf);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  fi->fh = std::stoi(buf);
  return 0; 
}


// Function to open a file
int enfs_open(const char* path, struct fuse_file_info* fi) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "35" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(fi->flags);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buf[BUF_SIZE];
  int bytes = SSL_read(ssl, buf, sizeof buf);
  buf[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buf);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  fi->fh = std::stoi(buf);
  return 0; 
}


// Function to read from a file
int enfs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "36" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(fi->fh) + "&&" + std::to_string(fi->flags) + "&&" +
                    std::to_string(size) + "&&" + std::to_string(offset);

  SSL_write(ssl, msg.c_str(), msg.size());
  unsigned char enc[size];
  memset(enc, 0, size);
  size_t enclen = SSL_read(ssl, enc, size);
  unsigned char dec[enclen];
  memset(dec, 0, enclen);
  printHex("Enc data", enc, enclen);

  size_t c = 0;
  while (c < enclen) {
    AES_decrypt(enc + c, dec + c, &dec_key);
    c += AES_BLOCK_SIZE;
  }
  memset(buf, 0, size);
  memcpy(buf, dec, enclen);

  printHex("Dec data", dec, size);

  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", enc);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  return enclen;
}


// Function to write to a file
int enfs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  const size_t enclen = ((size + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  unsigned char enc[enclen], padin[enclen];
  memset(enc, 0, enclen);
  memset(padin, 0, enclen);
  memcpy(padin, buf, size);

  size_t c = 0;
  while (c < enclen) {
    AES_encrypt(padin + c, enc + c, &enc_key);
    c += AES_BLOCK_SIZE;
  }

  printHex("Data", (unsigned char*)buf, size);
  printHex("Enc data", enc, enclen);

  std::string msg = "37" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(fi->fh) + "&&" + std::to_string(fi->flags) + "&&" +
                    std::to_string(enclen) + "&&" + std::to_string(offset);

  SSL_write(ssl, msg.c_str(), msg.size());
  SSL_write(ssl, enc, enclen);
  char buff[BUF_SIZE];
  memset(buff, 0, BUF_SIZE);
  int bytes = SSL_read(ssl, buff, sizeof buff);
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }

  return std::stol(std::string(buff).substr(0, bytes));
}


// Function to truncate a file
int enfs_truncate(const char* path, off_t newsize) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "38" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(newsize);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buf[BUF_SIZE];
  memset(buf, 0, BUF_SIZE);
  int bytes = SSL_read(ssl, buf, sizeof buf);
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buf);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buf[0] == '-') {
    return -1;
  }

  return 0;
}


// Function to delete a directory
int enfs_rmdir(const char* path) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "39" + ENFS_DATA->code + "&&" + path;
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


// Function to delete a file
int enfs_unlink(const char* path) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "3A" + ENFS_DATA->code + "&&" + path;
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


// Function to change the access time and last modified time
int enfs_utime(const char* path, struct utimbuf *ubuf) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "3B" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(ubuf->actime) + "&&" + std::to_string(ubuf->modtime);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


// Function to change the permissions of a file / directory
int enfs_chmod(const char* path, mode_t mode) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "3C" + ENFS_DATA->code + "&&" + path + "&&" + std::to_string(mode);
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


// Function to rename a file / directory
int enfs_rename(const char* path, const char* newpath) {
  int server = connServer(ENFS_DATA->host, SERVER_PORT);
  SSL_CTX* ctx = init();
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  if (SSL_connect(ssl) == -1) {
    fprintf(stderr, "Unable to connect to server\n");
    return -1;
  }

  std::string msg = "3D" + ENFS_DATA->code + "&&" + path + "&&" + newpath;
  SSL_write(ssl, msg.c_str(), msg.size());
  char buff[BUF_SIZE];
  int bytes = SSL_read(ssl, buff, sizeof buff);
  buff[bytes] = 0;
  printf("Sent: \"%s\"\n", msg.c_str());
  printf("Received: \"%s\"\n", buff);
  SSL_free(ssl);
  close(server);
  SSL_CTX_free(ctx);

  if (buff[0] == '-') {
    return -1;
  }
  return 0;
}


int enfs_getxattr(const char* path, const char* name, char* value, size_t size) {
  if (strncmp(name, "security.", 9) == 0) {
    return -ENODATA;
  }
  return 0;
}

int enfs_access(const char* path, int mask) {
  return 0;
}

void* enfs_init(struct fuse_conn_info* conn) {
  return ENFS_DATA;
}


int initENFS(const std::string& host, const std::string& path, int argc, char* argv[]) {
  struct fuse_operations enfs_oper;
  initFUSEoper::init(enfs_oper);

  std::string fpath = path + "/code";
  FILE* fp = fopen(fpath.c_str(), "r");
  if (fp == NULL) {
    fprintf(stderr, "Unable to open code file\n");
    return 1;
  }
  char buf[BUF_SIZE];
  memset(buf, 0, BUF_SIZE);
  fgets(buf, BUF_SIZE, fp);
  buf[strlen(buf)] = '\0';
  fclose(fp);

  fuse_data fdi(host, path, buf);
  return fuse_main(argc, argv, &enfs_oper, &fdi);
}
