# detect/ 构建说明

## ndk-build（推荐）

将本目录当作 jni 源目录：

```
# 项目根: detect/Android.mk
cd detect
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk \
    APP_ABI=arm64-v8a,armeabi-v7a APP_PLATFORM=android-24
```

`Android.mk`：

```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := fridadetect
LOCAL_SRC_FILES := frida_detect.c jni_bridge.c
LOCAL_CFLAGS := -D_GNU_SOURCE -Wall -O2
include $(BUILD_SHARED_LIBRARY)
```

产物 `libs/<abi>/libfridadetect.so`，Java 侧 `detect/FridaDetect.java`
通过 `System.loadLibrary("fridadetect")` 加载。

## 独立 CLI 二进制（root/adb shell 下自测）

```sh
# 源文件里再留一个 main，见 test_main.c
$CC -D_GNU_SOURCE -O2 -o fridadetect_cli frida_detect.c test_main.c -ldl -lpthread
adb push fridadetect_cli /data/local/tmp/ && adb shell /data/local/tmp/fridadetect_cli
```

## 依赖

- bionic (`dl_iterate_phdr`, `pthread_getname_np` 自 API 24+)
- 无第三方依赖；所有 procfs 读取有 raw syscall 直通路径
