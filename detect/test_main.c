// test_main.c — CLI 自测入口（adb push 到 /data/local/tmp 跑）
#define _GNU_SOURCE
#include "frida_detect.h"
#include <stdio.h>

int main(void)
{
    fr_scan_report r = fr_detect_all();
    printf("=== Frida Fingerprint Check ===\n");
    printf("1. thread name hits      : %d\n", r.thread_hits);
    for (int i = 0; i < r.thread_hits && i < 8; i++)
        printf("     %s\n", r.thread_names[i]);
    printf("2. maps keyword hits     : %d (anon exec pages: %d)\n",
           r.maps_keyword_hits, r.maps_anon_exec_pages);
    printf("3. net score             : %d, port27042=%d (2=dbus)\n", r.net_score, r.port_27042);
    printf("4. phdr hits             : %d\n", r.phdr_hits);
    for (int i = 0; i < r.phdr_hits && i < 8; i++)
        printf("     %s\n", r.lib_names[i]);
    printf("5. code anomalies        : %d\n", r.code_anomalies);
    printf("7. tracer_pid=%d seccomp=%d\n", r.tracer_pid, r.seccomp_mode);
    printf("8. fs hits               : %d\n", r.fs_hits);
    for (int i = 0; i < r.fs_hits && i < 8; i++)
        printf("     %s\n", r.fs_paths[i]);
    printf("--- score=%d detected=%s ---\n", r.score, r.detected ? "YES" : "no");
    return r.detected ? 1 : 0;
}
