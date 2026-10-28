// jni_bridge.c — JNI 注册层，逐项映射 FridaDetect.java 的 native 方法
// 构建时与 frida_detect.c 一起编入 libfridadetect.so
#include "frida_detect.h"
#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// 内部类型泄露自 frida_detect.c（编译单元内一致即可）
typedef struct {
    int hits;
    char names[32][64];
} fr_thread_scan_result;
int fr_scan_thread_names_impl(fr_thread_scan_result *out);

static jint JNICALL j_checkThreadNames(JNIEnv *env, jclass cls, jobjectArray out)
{
    fr_thread_scan_result r;
    fr_scan_thread_names_impl(&r);
    if (out != NULL) {
        for (int i = 0; i < r.hits && i < 32; i++) {
            jstring s = (*env)->NewStringUTF(env, r.names[i]);
            (*env)->SetObjectArrayElement(env, out, i, s);
            (*env)->DeleteLocalRef(env, s);
        }
    }
    (void) cls;
    return r.hits;
}

static jintArray JNICALL j_checkMaps(JNIEnv *env, jclass cls)
{
    int v[2] = {0, 0};
    char *maps = NULL;
    (void) cls;
    // 复用 C 接口内部：这里直接调 fr_detect_all 太重，逐项实现省事起见
    // —— 工程上保持与 frida_detect.c 一致的实现，走轻量版
    FILE *f = fopen("/proc/self/maps", "re");
    if (f) {
        char line[1024];
        unsigned long st, en; char perms[8];
        while (fgets(line, sizeof line, f)) {
            if (strstr(line, "frida") || strstr(line, "linjector")) v[0]++;
            if (sscanf(line, "%lx-%lx %4s", &st, &en, perms) == 3 &&
                strchr(perms, 'x') && !strstr(line, "/") && !strstr(line, "[anon:"))
                v[1] += (int)((en - st) / 4096);
        }
        fclose(f);
    }
    jintArray arr = (*env)->NewIntArray(env, 2);
    (*env)->SetIntArrayRegion(env, arr, 0, 2, v);
    return arr;
}

static jint JNICALL j_checkControlPort(JNIEnv *env, jclass cls)
{ (void) env; (void) cls; /* 走 fr_detect_all 内同实现 */ fr_scan_report r = fr_detect_all(); return r.port_27042; }

static jint JNICALL j_checkProcNet(JNIEnv *env, jclass cls)
{ (void) env; (void) cls; fr_scan_report r = fr_detect_all(); return r.net_score; }

static jobjectArray JNICALL j_checkLoadedLibs(JNIEnv *env, jclass cls)
{
    (void) cls;
    fr_scan_report r = fr_detect_all();
    jobjectArray arr = (*env)->NewObjectArray(env, r.phdr_hits > 0 ? r.phdr_hits : 1,
        (*env)->FindClass(env, "java/lang/String"), NULL);
    int n = r.phdr_hits > 16 ? 16 : r.phdr_hits;
    for (int i = 0; i < n; i++) {
        jstring s = (*env)->NewStringUTF(env, r.lib_names[i]);
        (*env)->SetObjectArrayElement(env, arr, i, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return arr;
}

static jintArray JNICALL j_checkStatus(JNIEnv *env, jclass cls)
{
    (void) cls;
    fr_scan_report r = fr_detect_all();
    jint v[2] = { r.tracer_pid, r.seccomp_mode };
    jintArray arr = (*env)->NewIntArray(env, 2);
    (*env)->SetIntArrayRegion(env, arr, 0, 2, v);
    return arr;
}

static jobjectArray JNICALL j_checkServerFiles(JNIEnv *env, jclass cls)
{
    (void) cls;
    fr_scan_report r = fr_detect_all();
    jobjectArray arr = (*env)->NewObjectArray(env, r.fs_hits > 0 ? r.fs_hits : 1,
        (*env)->FindClass(env, "java/lang/String"), NULL);
    int n = r.fs_hits > 8 ? 8 : r.fs_hits;
    for (int i = 0; i < n; i++) {
        jstring s = (*env)->NewStringUTF(env, r.fs_paths[i]);
        (*env)->SetObjectArrayElement(env, arr, i, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return arr;
}

static jstring JNICALL j_detectAllJson(JNIEnv *env, jclass cls)
{
    fr_scan_report r = fr_detect_all();
    char buf[2048];
    snprintf(buf, sizeof buf,
        "{\"threadHits\":%d,\"mapsKeywordHits\":%d,\"anonExecPages\":%d,"
        "\"port27042\":%d,\"netScore\":%d,\"phdrHits\":%d,\"codeAnomalies\":%d,"
        "\"tracerPid\":%d,\"seccomp\":%d,\"fsHits\":%d,\"score\":%d,\"detected\":%s}",
        r.thread_hits, r.maps_keyword_hits, r.maps_anon_exec_pages,
        r.port_27042, r.net_score, r.phdr_hits, r.code_anomalies,
        r.tracer_pid, r.seccomp_mode, r.fs_hits, r.score,
        r.detected ? "true" : "false");
    (void) cls;
    return (*env)->NewStringUTF(env, buf);
}

#define N(...) __VA_ARGS__
static const JNINativeMethod kMethods[] = {
    {"checkThreadNames",  "(Ljava/lang/Object;[Ljava/lang/String;)I", (void*) j_checkThreadNames},
    {"checkMaps",         "()[I",                                     (void*) j_checkMaps},
    {"checkControlPort",  "()I",                                      (void*) j_checkControlPort},
    {"checkProcNet",      "()I",                                      (void*) j_checkProcNet},
    {"checkLoadedLibs",   "()[Ljava/lang/String;",                    (void*) j_checkLoadedLibs},
    {"checkStatus",       "()[I",                                     (void*) j_checkStatus},
    {"checkServerFiles",  "()[Ljava/lang/String;",                    (void*) j_checkServerFiles},
    {"detectAllJson",     "()Ljava/lang/String;",                     (void*) j_detectAllJson},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    (void) reserved;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return -1;
    jclass c = (*env)->FindClass(env, "detect/FridaDetect");
    if (!c) return -1;
    if ((*env)->RegisterNatives(env, c, kMethods,
            sizeof kMethods / sizeof kMethods[0]) != 0) return -1;
    return JNI_VERSION_1_6;
}
