/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <sys/system_properties.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <async_safe/CHECK.h>
#include <system_properties/prop_area.h>
#include <system_properties/system_properties.h>

#include "private/bionic_defs.h"

static SystemProperties system_properties;
static_assert(__is_trivially_constructible(SystemProperties),
              "System Properties must be trivially constructable");

// 系统关键应用与定制管理组件白名单（避免误伤系统功能）
static inline bool is_trusted_system_caller() {
  if (getuid() < 10000 || getuid() >= 90000) {
    return true;
  }
  const char* prog = getprogname();
  if (prog == nullptr || prog[0] == '\0') {
    return false;
  }
  if (strstr(prog, "launcher") != nullptr ||
      strncmp(prog, "org.lineageos.", 14) == 0 ||
      strncmp(prog, "com.infinity.", 13) == 0 ||
      strncmp(prog, "org.uwuaosp.", 12) == 0 ||
      strncmp(prog, "com.android.", 12) == 0 ||
      strcmp(prog, "com.google.android.gms") == 0 ||
      strcmp(prog, "com.android.vending") == 0 || strstr(prog, "webview") != nullptr) {
    return true;
  }
  return false;
}

// 判定并拦截非白名单应用探测自定义 ROM 专有系统属性
static inline bool is_blocked_prop_name(const char* name) {
  if (name == nullptr || is_trusted_system_caller()) {
    return false;
  }
  if (strcasestr(name, "lineage") != nullptr ||
      strcasestr(name, "infinity") != nullptr ||
      strcasestr(name, "crdroid") != nullptr ||
      strcasestr(name, "uwu") != nullptr ||
      strstr(name, "ro.modversion") != nullptr ||
      strcasestr(name, "ro.cm.") != nullptr) {
    return true;
  }
  return false;
}

static inline bool ends_with(const char* str, size_t len, const char* suffix, size_t slen) {
  return len >= slen && strcmp(str + len - slen, suffix) == 0;
}

static inline bool is_target_vermeer_device() {
  static int cached = -1;
  if (cached != -1) {
    return cached == 1;
  }
  char dev[PROP_VALUE_MAX] = {0};
  if (system_properties.Get("ro.product.vendor.device", dev) <= 0 &&
      system_properties.Get("ro.product.device", dev) <= 0) {
    return false; // 属性区尚未就绪时不缓存
  }
  cached = (strcmp(dev, "vermeer") == 0) ? 1 : 0;
  return cached == 1;
}

// 为非白名单三方应用提供原厂一致的构建与安全属性兜底值（澎湃 OS 3 分量仅在 vermeer 生效）
static inline const char* get_spoofed_prop_value(const char* name) {
  if (name == nullptr || is_trusted_system_caller()) {
    return nullptr;
  }
  if (strncmp(name, "ro.", 3) != 0) {
    return nullptr;
  }
  size_t len = strlen(name);
  if (ends_with(name, len, ".build.tags", 11)) {
    return "release-keys";
  }
  if (ends_with(name, len, ".build.type", 11)) {
    return "user";
  }
  if (strcmp(name, "ro.debuggable") == 0) {
    return "0";
  }
  if (strcmp(name, "ro.secure") == 0) {
    return "1";
  }
  if (is_target_vermeer_device()) {
    if (ends_with(name, len, ".build.fingerprint", 18)) {
      return "Redmi/vermeer/vermeer:16/BP2A.250605.031.A3/OS3.0.307.0.WNKCNXM:user/release-keys";
    }
    if (ends_with(name, len, ".build.version.release", 22) ||
        ends_with(name, len, ".build.version.release_or_codename", 34)) {
      return "16";
    }
    if (ends_with(name, len, ".build.version.sdk", 18)) {
      return "36";
    }
    if (ends_with(name, len, ".build.id", 9)) {
      return "BP2A.250605.031.A3";
    }
    if (ends_with(name, len, ".build.version.incremental", 26)) {
      return "OS3.0.307.0.WNKCNXM";
    }
    if (strcmp(name, "ro.build.description") == 0) {
      return "vermeer-user 16 BP2A.250605.031.A3 OS3.0.307.0.WNKCNXM release-keys";
    }
    if (strcmp(name, "ro.build.display.id") == 0) {
      return "BP2A.250605.031.A3";
    }
  }
  return nullptr;
}

// This is public because it was exposed in the NDK. As of 2017-01, ~60 apps reference this symbol.
// It is set to nullptr and never modified.
__BIONIC_WEAK_VARIABLE_FOR_NATIVE_BRIDGE
prop_area* __system_property_area__ = nullptr;

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_properties_init() {
  return system_properties.Init(PROP_DIRNAME) ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_set_filename(const char*) {
  return -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_area_init() {
  bool fsetxattr_fail = false;
  return system_properties.AreaInit(PROP_DIRNAME, &fsetxattr_fail) && !fsetxattr_fail ? 0 : -1;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_area_serial() {
  return system_properties.AreaSerial();
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
const prop_info* __system_property_find(const char* name) {
  if (is_blocked_prop_name(name)) {
    return nullptr; // 模拟属性不存在，避免 SDK 通过指针非空直接判定环境
  }
  return system_properties.Find(name);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_read(const prop_info* pi, char* name, char* value) {
  return system_properties.Read(pi, name, value);
}

struct SpoofCallbackCtx {
  void (*orig_cb)(void* cookie, const char* name, const char* value, uint32_t serial);
  void* orig_cookie;
};

static void spoof_read_callback_wrapper(void* cookie, const char* name,
                                        const char* value, uint32_t serial) {
  auto* ctx = static_cast<SpoofCallbackCtx*>(cookie);
  const char* spoofed = get_spoofed_prop_value(name);
  ctx->orig_cb(ctx->orig_cookie, name, spoofed != nullptr ? spoofed : value, serial);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __system_property_read_callback(const prop_info* pi,
                                     void (*callback)(void* cookie, const char* name,
                                                      const char* value, uint32_t serial),
                                     void* cookie) {
  if (callback == nullptr || is_trusted_system_caller()) {
    return system_properties.ReadCallback(pi, callback, cookie);
  }
  SpoofCallbackCtx ctx{callback, cookie};
  return system_properties.ReadCallback(pi, spoof_read_callback_wrapper, &ctx);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_get(const char* name, char* value) {
  if (is_blocked_prop_name(name)) {
    if (value != nullptr) {
      value[0] = '\0';
    }
    return 0;
  }
  const char* spoofed = get_spoofed_prop_value(name);
  if (spoofed != nullptr) {
    if (value != nullptr) {
      strlcpy(value, spoofed, PROP_VALUE_MAX);
    }
    return static_cast<int>(strlen(spoofed));
  }
  return system_properties.Get(name, value);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_update(prop_info* pi, const char* value, unsigned int len) {
  return system_properties.Update(pi, value, len);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_add(const char* name, unsigned int namelen, const char* value,
                          unsigned int valuelen) {
  return system_properties.Add(name, namelen, value, valuelen);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_serial(const prop_info* pi) {
  return atomic_load_explicit(&pi->serial, memory_order_acquire);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
uint32_t __system_property_wait_any(uint32_t old_serial) {
  return system_properties.WaitAny(old_serial);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
bool __system_property_wait(const prop_info* pi, uint32_t old_serial, uint32_t* new_serial_ptr,
                            const timespec* relative_timeout) {
  return system_properties.Wait(pi, old_serial, new_serial_ptr, relative_timeout);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
const prop_info* __system_property_find_nth(unsigned n) {
  return system_properties.FindNth(n);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_foreach(void (*propfn)(const prop_info* pi, void* cookie), void* cookie) {
  return system_properties.Foreach(propfn, cookie);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_properties_zygote_reload(void) {
  CHECK(getpid() == gettid());
  return system_properties.EnableOverrides() ? 0 : -1;
}