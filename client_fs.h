
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

#ifndef _CLIENT_FS_H
#define _CLIENT_FS_H

#define FUSE_USE_VERSION 30

#include <string>
#include <vector>

#include <fuse.h>
#include <openssl/aes.h>

#define SERVER_PORT 5050
#define BUF_SIZE 4096

#define AES_KEY_SIZE 256
#define AES_KEY_FILE "aeskey.pem"


extern char upass[26];
extern AES_KEY enc_key, dec_key; 


struct fuse_data {
  std::string host;
  std::string code;
  std::string path;
  fuse_data(const std::string& host, const std::string& path, const std::string& code) {
    try {
      this->host = host;
      this->code = code;
      this->path = path;
    } catch (const char* err) {
      throw err;
    }
  }
};

#define ENFS_DATA ((fuse_data*)fuse_get_context()->private_data)

std::vector<std::string> split(const std::string &s, char delim);
int connServer(const std::string& serv, int port);
int pem_passwd_cb(char *buf, int size, int rwflag, void *pass);

int enfs_getattr(const char* path, struct stat* statbuf);
int enfs_mkdir(const char *path, mode_t mode);
int enfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi);
int enfs_create(const char* path, mode_t mode, struct fuse_file_info* fi);
int enfs_open(const char* path, struct fuse_file_info* fi);
int enfs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
int enfs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi);
int enfs_truncate(const char* path, off_t newsize);
int enfs_rmdir(const char* path);
int enfs_unlink(const char* path);
int enfs_utime(const char* path, struct utimbuf *ubuf);
int enfs_chmod(const char* path, mode_t mode);
int enfs_rename(const char* path, const char* newpath);
int enfs_getxattr(const char* path, const char* name, char* value, size_t size);
int enfs_access(const char* path, int mask);
void* enfs_init(struct fuse_conn_info* conn);

struct initFUSEoper {
  static void init(struct fuse_operations& enfs_oper) {
    enfs_oper.getattr     = enfs_getattr;
    enfs_oper.readlink    = NULL;
    enfs_oper.getdir      = NULL;
    enfs_oper.mknod       = NULL;
    enfs_oper.mkdir       = enfs_mkdir;
    enfs_oper.unlink      = enfs_unlink;
    enfs_oper.rmdir       = enfs_rmdir;
    enfs_oper.symlink     = NULL;
    enfs_oper.rename      = enfs_rename;
    enfs_oper.link        = NULL;
    enfs_oper.chmod       = enfs_chmod;
    enfs_oper.chown       = NULL;
    enfs_oper.truncate    = enfs_truncate;
    enfs_oper.utime       = enfs_utime;
    enfs_oper.utimens     = NULL;
    enfs_oper.open        = enfs_open;
    enfs_oper.read        = enfs_read;
    enfs_oper.write       = enfs_write;
    enfs_oper.statfs      = NULL;
    enfs_oper.flush       = NULL;
    enfs_oper.release     = NULL;
    enfs_oper.fsync       = NULL;
    enfs_oper.setxattr    = NULL;
    enfs_oper.getxattr    = enfs_getxattr;
    enfs_oper.listxattr   = NULL;
    enfs_oper.removexattr = NULL;
    enfs_oper.opendir     = NULL;
    enfs_oper.readdir     = enfs_readdir;
    enfs_oper.releasedir  = NULL;
    enfs_oper.fsyncdir    = NULL;
    enfs_oper.init        = enfs_init;
    enfs_oper.destroy     = NULL;
    enfs_oper.access      = NULL;
    enfs_oper.create      = enfs_create;
    enfs_oper.ftruncate   = NULL;
    enfs_oper.fgetattr    = NULL;
    enfs_oper.write_buf   = NULL;
    enfs_oper.read_buf    = NULL;
    enfs_oper.fallocate   = NULL;
    enfs_oper.lock        = NULL;
    enfs_oper.poll        = NULL;
  }
};

int initENFS(const std::string& host, const std::string& path, int argc, char* argv[]);

#endif
