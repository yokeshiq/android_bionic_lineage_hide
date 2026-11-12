/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "private/bionic_fdtrack.h"
#include "private/bionic_fortify.h"

extern "C" int __openat(int, const char*, int, int);

// 判定当前调用进程是否属于系统特权或白名单进程
static inline bool is_whitelisted_lineage_caller() {
  if (getuid() < 10000) {
    return true;
  }
  const char* prog = getprogname();
  if (prog != nullptr) {
    if (strstr(prog, "launcher") != nullptr ||
        strncmp(prog, "org.lineageos.", 14) == 0 ||
        strcmp(prog, "com.android.systemui") == 0 ||
        strcmp(prog, "com.android.settings") == 0) {
      return true;
    }
  }
  return false;
}

// 判定并拦截三方应用刺探 LineageOS 专有静态节点、sepolicy 策略与 idmap 缓存
static inline bool is_lineage_static_node(const char* pathname) {
  if (pathname == nullptr || getuid() < 10000) {
    return false;
  }

  // 1. 放行应用私有数据目录，但严禁放行 /data/resource-cache/ 下的 Lineage idmap 缓存
  if (strncmp(pathname, "/data/", 6) == 0) {
    if (strstr(pathname, "resource-cache") != nullptr &&
        strcasestr(pathname, "lineage") != nullptr) {
      return true;
    }
    return false;
  }

  // 2. 进程白名单放行
  if (is_whitelisted_lineage_caller()) {
    return false;
  }

  // 3. 拦截三方应用刺探 SELinux 策略规则文件（阻断 ROM detected (a)）
  if (strstr(pathname, "/etc/selinux/") != nullptr) {
    return true;
  }

  // 4. 拦截系统分区中的 Lineage 专有特征文件与 Overlay APK
  if (strcasestr(pathname, "lineage") != nullptr) {
    return true;
  }
  if (strstr(pathname, "addon.d") != nullptr) {
    return true;
  }
  if (strstr(pathname, "hwservice_contexts") != nullptr) {
    return true;
  }
  if (strstr(pathname, "platform-infinity") != nullptr) {
    return true;
  }

  return false;
}

// 判断目标文件是否为进程内存映射表（/proc/*/maps 或 smaps）
static inline bool is_proc_maps_target(int dirfd, const char* pathname) {
  if (pathname == nullptr) {
    return false;
  }

  if (strncmp(pathname, "/proc/", 6) == 0) {
    const char* sub = pathname + 6;
    if (strcmp(sub, "self/maps") == 0 || strcmp(sub, "self/smaps") == 0 ||
        strcmp(sub, "thread-self/maps") == 0 || strcmp(sub, "thread-self/smaps") == 0) {
      return true;
    }
    const char* slash = strchr(sub, '/');
    if (slash != nullptr && slash > sub) {
      for (const char* c = sub; c < slash; ++c) {
        if (!isdigit(static_cast<unsigned char>(*c))) {
          return false;
        }
      }
      return (strcmp(slash + 1, "maps") == 0 || strcmp(slash + 1, "smaps") == 0);
    }
    return false;
  }

  // 兼容 openat(proc_dir_fd, "maps", O_RDONLY) 相对路径方式
  if (dirfd != AT_FDCWD && (strcmp(pathname, "maps") == 0 || strcmp(pathname, "smaps") == 0)) {
    char fd_link[64];
    char target_dir[64];
    snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", dirfd);
    ssize_t n = readlink(fd_link, target_dir, sizeof(target_dir) - 1);
    if (n > 0) {
      target_dir[n] = '\0';
      if (strncmp(target_dir, "/proc/", 6) == 0) {
        return true;
      }
    }
  }
  return false;
}

// 过滤 /proc/*/maps 中包含 lineage 的 APK 与 Overlay 映射行（保留 ART .art/.oat 映射）
static int filter_proc_maps_fd(int dirfd, const char* pathname, int flags, int raw_fd) {
  if (raw_fd < 0 || (flags & O_ACCMODE) != O_RDONLY || (flags & O_PATH) != 0) {
    return raw_fd;
  }
  if (is_whitelisted_lineage_caller() || !is_proc_maps_target(dirfd, pathname)) {
    return raw_fd;
  }

  // 系统完全进入桌面后再启用，避开所有早期启动进程
  static bool s_boot_completed = false;
  if (!s_boot_completed) {
    char boot_val[PROP_VALUE_MAX] = {0};
    if (__system_property_get("sys.boot_completed", boot_val) <= 0 || boot_val[0] != '1') {
      return raw_fd;
    }
    s_boot_completed = true;
  }

  unsigned int mfd_flags = (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0U;
  int mfd = memfd_create("maps", mfd_flags);
  if (mfd < 0) {
    return raw_fd;
  }

  FILE* fp = fdopen(raw_fd, "r");
  if (fp == nullptr) {
    close(mfd);
    return raw_fd;
  }

  char* line = nullptr;
  size_t cap = 0;
  ssize_t nread;
  while ((nread = getline(&line, &cap, fp)) > 0) {
    bool is_lineage_apk_or_overlay =
        (strcasestr(line, "lineage") != nullptr) &&
        (strcasestr(line, ".apk") != nullptr || strstr(line, "/overlay/") != nullptr);
    if (!is_lineage_apk_or_overlay) {
      if (write(mfd, line, static_cast<size_t>(nread)) < 0) {
        break;
      }
    }
  }
  free(line);
  fclose(fp);  // 自动关闭 raw_fd
  lseek(mfd, 0, SEEK_SET);
  return mfd;
}

static inline int force_O_LARGEFILE(int flags) {
#if defined(__LP64__)
  return flags; // No need, and aarch64's strace gets confused.
#else
  return flags | O_LARGEFILE;
#endif
}

static inline bool needs_mode(int flags) {
  return ((flags & O_CREAT) == O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE);
}

int creat(const char* pathname, mode_t mode) {
  return open(pathname, O_CREAT | O_TRUNC | O_WRONLY, mode);
}
__strong_alias(creat64, creat);

int open(const char* pathname, int flags, ...) {
  if (is_lineage_static_node(pathname)) {
    errno = ENOENT;
    return -1;
  }

  mode_t mode = 0;

  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int fd = __openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), mode);
  fd = filter_proc_maps_fd(AT_FDCWD, pathname, flags, fd);
  return FDTRACK_CREATE(fd);
}
__strong_alias(open64, open);

int __open_2(const char* pathname, int flags) {
  if (is_lineage_static_node(pathname)) {
    errno = ENOENT;
    return -1;
  }

  if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
  int fd = __openat(AT_FDCWD, pathname, force_O_LARGEFILE(flags), 0);
  fd = filter_proc_maps_fd(AT_FDCWD, pathname, flags, fd);
  return FDTRACK_CREATE_NAME("open", fd);
}

int openat(int fd, const char *pathname, int flags, ...) {
  if (is_lineage_static_node(pathname)) {
    errno = ENOENT;
    return -1;
  }

  mode_t mode = 0;

  if (needs_mode(flags)) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }

  int res_fd = __openat(fd, pathname, force_O_LARGEFILE(flags), mode);
  res_fd = filter_proc_maps_fd(fd, pathname, flags, res_fd);
  return FDTRACK_CREATE_NAME("openat", res_fd);
}
__strong_alias(openat64, openat);

int __openat_2(int fd, const char* pathname, int flags) {
  if (is_lineage_static_node(pathname)) {
    errno = ENOENT;
    return -1;
  }

  if (needs_mode(flags)) __fortify_fatal("open: called with O_CREAT/O_TMPFILE but no mode");
  int res_fd = __openat(fd, pathname, force_O_LARGEFILE(flags), 0);
  res_fd = filter_proc_maps_fd(fd, pathname, flags, res_fd);
  return FDTRACK_CREATE_NAME("openat", res_fd);
}
