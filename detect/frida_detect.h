#ifndef FRIDA_DETECT_H
#define FRIDA_DETECT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // 1. 线程名
    int     thread_hits;            // gum-js-loop / frida-* 命中数
    char    thread_names[32][64];

    // 2. maps
    int     maps_keyword_hits;       // frida/gadget/linjector 字面命中
    int     maps_anon_exec_pages;    // 无背书匿名可执行页（JIT 误报项，见矩阵）

    // 3. 网络
    int     net_score;               // /proc/net/tcp + unix 命中加权
    int     port_27042;              // 0=关 1=开 2=开且 D-Bus 回 REJECTED

    // 4. 已加载 so
    int     phdr_hits;
    char    lib_names[16][256];

    // 5. 代码段合法性
    int     code_anomalies;         // 哨兵函数落在匿名 RX 的数量

    // 7. status
    int     tracer_pid;              // -1=读不到
    int     seccomp_mode;

    // 8. 文件系统
    int     fs_hits;
    char    fs_paths[8][256];

    // 汇总
    int     score;                  // 0-100+ 加权
    bool    detected;               // score >= 30
} fr_scan_report;

fr_scan_report fr_detect_all(void);

// 单项细粒度接口（Java JNI 层按项调用用）
struct _fr_thread_scan_result;
int  fr_scan_thread_names(struct _fr_thread_scan_result *out); // 内部类型，走 JNI 封装请用 fr_detect_all
int  fr_crash_backtrace_contains_frida(const char *backtrace);

#ifdef __cplusplus
}
#endif

#endif // FRIDA_DETECT_H
