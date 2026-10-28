// cmp_task_diff.sh — raw getdents64 vs opendir/readdir 同时刻对照脚本
// 【待实测】本轮仅静态分析，未在任何设备上执行。按下方判定标准跑。
//
// 用法（待授权后在有原版 frida 的设备上执行）:
//   1. 编译: $CC -D_GNU_SOURCE -O2 -o taskdiff cmp_task_diff.c
//   2. adb push taskdiff /data/local/tmp/ && chmod +x
//   3. 后台运行 ./taskdiff snap &  （持续采样两个通道，写 /data/local/tmp/taskdiff.log）
//   4. PC 侧: frida -U -n <目标进程> 注入任意脚本（让 agent 起来、产生 frida 线程）
//   5. kill %1 后取回 log 对比。
//
// 判定标准（预期结果，源码可证部分已锚定）:
//   若 cloak 生效（ThreadListCloaker 存在，cloak.vala:199-216，
//   DirListCloaker 挂 opendir/readdir，cloak.vala:257-284）:
//     (a) opendir+readdir 通道的 /proc/self/task 条目数 < (b) raw getdents64 通道
//         差值 ≈ frida 线程数（gum-js-loop + gmain/gdbus + pool-*，通常 2~6 条）
//         且 (b) 通道中可看到 comm 名含 gum-js-loop 的 tid，(a) 通道中该 tid 缺失。
//   若 cloak 不生效（frida 未注入 / 已 detach / 魔改删了 cloak）:
//     两通道条目数相等（±1，因采样瞬间的自然线程退出/新建）。
//   任何情况下 (b) ≥ (a)：libc 层 hook 只能减不能增。
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int raw_getdents_count(int *found_frida_tid)
{
    int fd = (int) syscall(__NR_openat, AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int n = 0; char buf[4096];
    *found_frida_tid = 0;
    for (;;) {
        ssize_t k = (ssize_t) syscall(__NR_getdents64, fd, buf, sizeof buf);
        if (k <= 0) break;
        for (size_t off = 0; off < (size_t) k; ) {
            struct d64 { uint64_t ino; int64_t off2; unsigned short reclen; unsigned char type; char name[]; };
            struct d64 *d = (void *) (buf + off);
            off += d->reclen;
            if (isdigit((unsigned char) d->name[0])) n++;
        }
    }
    close(fd);
    return n;
}

static int libc_readdir_count(void)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "once";
    FILE *log = fopen("/data/local/tmp/taskdiff.log", "a");
    if (!log) log = stderr;
    for (;;) {
        int frida_tid = 0;
        int a = libc_readdir_count();
        int b = raw_getdents_count(&frida_tid);
        fprintf(log, "readdir=%d getdents64=%d diff=%d\n", a, b, b - a);
        fflush(log);
        if (strcmp(mode, "once") == 0) break;
        usleep(200000); // 5Hz 采样
    }
    return 0;
}
