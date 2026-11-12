/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// 判定并拦截三方应用刺探 LineageOS 专有静态节点、sepolicy 策略与 idmap 缓存
static inline bool is_lineage_static_node(const char* pathname) {
  if (pathname == nullptr || getuid() < 10000) {
    return false; // 系统特权进程（UID < 10000）直接放行
  }

  // 1. 放行应用私有数据目录，但严禁放行 /data/resource-cache/ 下的 Lineage idmap 缓存
  if (strncmp(pathname, "/data/", 6) == 0) {
    if (strstr(pathname, "resource-cache") != nullptr &&
        strcasestr(pathname, "lineage") != nullptr) {
      return true; // 拦截 /data/resource-cache/*lineage*
    }
    return false;
  }

  // 2. 进程白名单：放行桌面、系统UI、设置以及 Lineage 自带进程
  const char* prog = getprogname();
  if (prog != nullptr) {
    if (strstr(prog, "launcher") != nullptr ||
        strncmp(prog, "org.lineageos.", 14) == 0 ||
        strcmp(prog, "com.android.systemui") == 0 ||
        strcmp(prog, "com.android.settings") == 0) {
      return false;
    }
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

int lstat(const char* path, struct stat* sb) {
  if (is_lineage_static_node(path)) {
    errno = ENOENT;
    return -1;
  }
  return fstatat(AT_FDCWD, path, sb, AT_SYMLINK_NOFOLLOW);
}
__strong_alias(lstat64, lstat);