
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

#include "server_fs.h"

#include <vector>

#include <dirent.h>
#include <utime.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>


char upass[26];


int pem_passwd_cb(char *buf, int size, int rwflag, void *pass) {
  memcpy(buf, upass, strlen(upass) + 1);
  return (strlen(buf));
}


// Function to stat a file / directory
void fuse_getattr(SSL* ssl, std::string& key) {
  std::string::size_type pos = key.find("&&");
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos) + key.substr(pos + 2, std::string::npos);
    struct stat* st = (struct stat*)malloc(sizeof(struct stat));
    if (lstat(fpath.c_str(), st) == 0) {
      msg = std::to_string(st->st_mode) + ":" + std::to_string(st->st_nlink) + ":" + std::to_string(st->st_uid) + ":" +
            std::to_string(st->st_gid) + ":" + std::to_string(st->st_size) + ":" + std::to_string(st->st_blksize) + ":" +
            std::to_string(st->st_blocks) + ":" + std::to_string(st->st_atime) + ":" + std::to_string(st->st_ctime) +
            ":" + std::to_string(st->st_mtime);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "getattr", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to create a new directory
void fuse_mkdir(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    long mode = std::stol(key.substr(pos2 + 2, std::string::npos));
    if (mkdir(fpath.c_str(), mode) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "mkdir", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to read from a directory
void fuse_readdir(SSL* ssl, std::string& key) {
  std::string::size_type pos = key.find("&&");
  std::string msg = "";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos) + key.substr(pos + 2, std::string::npos);
    DIR *dp = opendir(fpath.c_str());
    if (dp != NULL) {
      struct dirent *de = readdir(dp);
      if (de != 0) {
        do {
          msg += std::string(de->d_name) + ":";
        } while ((de = readdir(dp)) != NULL);
        res = "SUCCESS";
      }
    }
  }
  printf("%10s: [%7s] [%s]\n", "readir", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to create a new file
void fuse_creat(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  int mode = 0;
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    mode = std::stoi(key.substr(pos2 + 2, std::string::npos));
    int fd;
    if ((fd = creat(fpath.c_str(), mode)) != -1) {
      msg = std::to_string(fd);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "creat", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to open a file
void fuse_open(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    int flags = std::stoi(key.substr(pos2 + 2, std::string::npos));
    int fd;
    if ((fd = open(fpath.c_str(), flags)) != -1) {
      msg = std::to_string(fd);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "open", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to write to a file
void fuse_write(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    pos1 = key.find("&&", pos2 + 2);
    int fd = std::stoi(key.substr(pos2 + 2, pos1 - pos2 - 2));
    pos2 = key.find("&&", pos1 + 2);
    int flags = std::stoi(key.substr(pos1 + 2, pos2 - pos1 - 2));
    pos1 = key.find("&&", pos2 + 2);
    long size = std::stol(key.substr(pos2 + 2, pos1 - pos2 - 2));
    pos2 = key.find("&&", pos1 + 2);
    long offset = std::stol(key.substr(pos1 + 2, std::string::npos));
    unsigned char buf[size];
    memset(buf, 0, size);
    SSL_read(ssl, buf, size);
    int ret;
    if ((ret = pwrite(fd, buf, size, offset)) >= 0) {
      msg = std::to_string(ret);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "write", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to read read from a file
void fuse_read(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::vector<unsigned char> msg {'-'};
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    pos1 = key.find("&&", pos2 + 2);
    int fd = std::stoi(key.substr(pos2 + 2, pos1 - pos2 - 2));
    pos2 = key.find("&&", pos1 + 2);
    int flags = std::stoi(key.substr(pos1 + 2, pos2 - pos1 - 2));
    pos1 = key.find("&&", pos2 + 2);
    long size = std::stol(key.substr(pos2 + 2, pos1 - pos2 - 2));
    long offset = std::stol(key.substr(pos1 + 2, std::string::npos));
    unsigned char buf[size];
    memset(buf, 0, size);
    if (pread(fd, buf, size, offset) >= 0) {
      msg.clear();
      msg.insert(msg.end(), &buf[0], &buf[size]);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "read", res.c_str(), fpath.c_str());
  SSL_write(ssl, &msg[0], msg.size());
}


// Function to trancate a file to a specific size
void fuse_truncate(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL"; 
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    long newsize = std::stol(key.substr(pos2 + 2, std::string::npos));
    if (truncate(fpath.c_str(), newsize) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "truncate", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to remove a directory
void fuse_rmdir(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1) + key.substr(pos1 + 2, std::string::npos);
    if (rmdir(fpath.c_str()) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "rmdir", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to delete a file
void fuse_unlink(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&");
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1) + key.substr(pos1 + 2, std::string::npos);
    if (unlink(fpath.c_str()) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "unlink", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to change the access time and last modified time
void fuse_utime(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    pos1 = key.find("&&", pos2 + 2);
    long actime = std::stol(key.substr(pos2 + 2, pos1 - pos2 - 2));
    long modtime = std::stol(key.substr(pos1 + 2, std::string::npos));
    const struct utimbuf *times = NULL; /*{actime, modtime};*/
    if (utime(fpath.c_str(), times) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "utime", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to change permissions of a file / directory
void fuse_chmod(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    long mode = std::stol(key.substr(pos2 + 2, std::string::npos));
    if (chmod(fpath.c_str(), mode) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "chmod", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function to rename a file / directory
void fuse_rename(SSL* ssl, std::string& key) {
  std::string::size_type pos1 = key.find("&&"), pos2;
  std::string msg = "-";
  std::string fpath = "";
  std::string npath = "";
  std::string res = "FAIL";
  if (pos1 != std::string::npos) {
    fpath = npath = "/tmp/.enfs/" + key.substr(0, pos1);
    pos2 = key.find("&&", pos1 + 2);
    fpath += key.substr(pos1 + 2, pos2 - pos1 - 2);
    npath += key.substr(pos2 + 2, std::string::npos);
    if (rename(fpath.c_str(), npath.c_str()) == 0) {
      msg = std::to_string(0);
      res = "SUCCESS";
    }
  }
  printf("%10s: [%7s] [%s]\n", "rename", res.c_str(), fpath.c_str());
  SSL_write(ssl, msg.c_str(), msg.size());
}


// Function that determine the ENFS file system call from client
// and call the appropriate ENFS server file system call
void clientFuse(SSL* ssl, std::string& key) {
  char ch = key[0];
  key.erase(0, 1);
  switch(ch) {
    case '1': {
      fuse_getattr(ssl, key);
      break;
    }
    case '2': {
      fuse_mkdir(ssl, key);
      break;
    }
    case '3': {
      fuse_readdir(ssl, key);
      break;
    }
    case '4': {
      fuse_creat(ssl, key);
      break;
    }
    case '5': {
      fuse_open(ssl, key);
      break;
    }
    case '6': {
      fuse_read(ssl, key);
      break;
    }
    case '7': {
      fuse_write(ssl, key);
      break;
    }
    case '8': {
      fuse_truncate(ssl, key);
      break;
    }
    case '9': {
      fuse_rmdir(ssl, key);
      break;
    }
    case 'A': {
      fuse_unlink(ssl, key);
      break;
    }
    case 'B': {
      fuse_utime(ssl, key);
      break;
    }
    case 'C': {
      fuse_chmod(ssl, key);
      break;
    }
    case 'D': {
      fuse_rename(ssl, key);
      break;
    }
  }
}
