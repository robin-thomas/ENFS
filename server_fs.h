
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

#ifndef _SERVER_FS_H
#define _SERVER_FS_H

#include <string>
#include <openssl/ssl.h>

extern char upass[26];

int pem_passwd_cb(char *buf, int size, int rwflag, void *pass);

void fuse_getattr(SSL* ssl, std::string& key);

void fuse_mkdir(SSL* ssl, std::string& key);

void fuse_readdir(SSL* ssl, std::string& key);

void fuse_creat(SSL* ssl, std::string& key);

void fuse_open(SSL* ssl, std::string& key);

void fuse_write(SSL* ssl, std::string& key);

void fuse_read(SSL* ssl, std::string& key);

void fuse_truncate(SSL* ssl, std::string& key);

void fuse_rmdir(SSL* ssl, std::string& key);

void fuse_unlink(SSL* ssl, std::string& key);

void fuse_utime(SSL* ssl, std::string& key);

void fuse_chmod(SSL* ssl, std::string& key);

void fuse_rename(SSL* ssl, std::string& key);

void clientFuse(SSL* ssl, std::string& key);



#endif
