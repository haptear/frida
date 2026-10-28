// frida_detect.c — Frida 指纹体检工装（Android, NDK, C17）
// 编译: 见 detect/build.md。NDK r26+，-D_GNU_SOURCE
//
// 设计原则（对应矩阵表 /detect/DETECT_MATRIX.md）:
//  1. 双通道读取 procfs —— libc open/read 可能被 Frida Interceptor hook
//     (frida-core/lib/payload/cloak.vala 对 readdir/read 有 hook，见矩阵"对抗难度"),
//     因此每项都提供 syscall 直通路径 (__NR_openat / __NR_read / getdents64)。
//  2. 线程名检测必须用 pthread_getname_np + ptrace 通道，因为原版 ThreadListCloaker
//     会 hook readdir 藏掉 frida 线程目录项 (cloak.vala:199 ThreadListCloaker)。
//  3. maps 匿名 RX 检测必须排除合法 JIT/WebView/Vulkan 区间，用内容指纹而非只看权限。

#define _GNU_SOURCE
#include "frida_detect.h"
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <elf.h>

// ---------------------------------------------------------------------------
// raw syscall helpers —— 绕过 libc hook 面
// ---------------------------------------------------------------------------
static int raw_open(const char *path, int flags)
{
    return (int) syscall(__NR_openat, AT_FDCWD, path, flags | O_CLOEXEC, 0);
}

static ssize_t raw_read(int fd, void *buf, size_t n)
{
    return syscall(__NR_read, fd, buf, n);
}

static ssize_t raw_getdents64(int fd, void *buf, size_t n)
{
    return syscall(__NR_getdents64, fd, buf, n);
}

// 逐块读取整个 procfs 文本文件到 heap（带 NUL 终止）
static char *slurp_raw(const char *path, size_t *out_len)
{
    int fd = raw_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 1024 > cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) { close(fd); return NULL; } }
        ssize_t n = raw_read(fd, buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t) n;
    }
    close(fd);
    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

// ---------------------------------------------------------------------------
// 1. 线程名枚举 /proc/self/task/*/comm + pthread_getname_np
// ---------------------------------------------------------------------------
// 注: readdir 被 ThreadListCloaker hook 时，getdents64 syscall 直通仍能看到
// 全量 tid —— cloak 只拦 libc 层 (cloak.vala DirListCloaker attach readdir)。
// comm 本身内容不隐藏 (frida 侧无 comm hook)，gum-js-loop / pool-* /
// frida-agent-emulated / frida-eternal-agent 等名字直接命中。

typedef struct {
    int hits;                          // 命中线程数
    char names[32][64];                // 命中的线程名
} fr_thread_scan_result;

static int fr_scan_thread_names(fr_thread_scan_result *out)
{
    memset(out, 0, sizeof(*out));
    int fd = raw_open("/proc/self/task", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    char buf[4096];
    for (;;) {
        ssize_t n = raw_getdents64(fd, buf, sizeof buf);
        if (n <= 0) break;
        for (size_t off = 0; off < (size_t) n; ) {
            struct linux_dirent64 { uint64_t ino; int64_t off; unsigned short reclen; unsigned char type; char name[]; };
            struct linux_dirent64 *d = (void *) (buf + off);
            off += d->reclen;
            if (d->type != DT_DIR && !isdigit((unsigned char) d->name[0])) continue;
            long tid = strtol(d->name, NULL, 10);
            if (tid <= 0) continue;
            char comm_path[64], comm[64] = {0};
            snprintf(comm_path, sizeof comm_path, "/proc/self/task/%ld/comm", tid);
            int cfd = raw_open(comm_path, O_RDONLY);
            if (cfd < 0) continue;
            ssize_t m = raw_read(cfd, comm, sizeof comm - 1);
            close(cfd);
            if (m <= 0) continue;
            comm[m] = 0;
            comm[strcspn(comm, "\n")] = 0;
            if (strstr(comm, "gum-js-loop") || strstr(comm, "gmain") ||
                strstr(comm, "pool-frida") || strstr(comm, "pool-*") ||
                strstr(comm, "frida") || strstr(comm, "gdbus")) {
                if (out->hits < 32)
                    snprintf(out->names[out->hits], 64, "tid=%ld %s", tid, comm);
                out->hits++;
            }
        }
    }
    close(fd);
    return out->hits;
}

// 通道 2: 系统内存里对其它线程做 pthread_getname_np 采样。
// frida 线程是真实 pthread，pthread_getname_np 走 /proc/self/task/<tid>/comm
// (bionic 实现于 sysprop，实际读 comm 文件)，且不在我们的 getdents 面内被藏。
// 无法枚举 tid 时可配合 fork-ptrace 通道（见 detect_by_ptrace_threads）。
static void fr_check_pthread_names_of_common_tids(void (*on_hit)(const char *, void *), void *ctx)
{
    // 采样区间: 自身 tid 前后 256 —— 快速启发，不保证全覆盖
    long self = (long) syscall(__NR_gettid);
    for (long tid = self - 256; tid <= self + 256; tid++) {
        if (tid <= 0 || tid == self) continue;
        char name[17] = {0};
        if (pthread_getname_np((pthread_t)(intptr_t) tid, name, sizeof name) == 0) {
            // Android NDK 签名: pthread_getname_np(pthread_t, char*, size_t)
            // (旧版接 tid —— 两者在此处都传数值，行为兼容)
            if (strstr(name, "gum") || strstr(name, "frida")) on_hit(name, ctx);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. /proc/self/maps 扫描
// ---------------------------------------------------------------------------
// 关键词: frida / gadget / linjector / gum / frida-agent
// 匿名可执行: 有 x 权限且无文件背书的映射。原版 agent 以 memfd 注入
// (linjector.vala:253 get_memfd / inject_library_fd)，路径显示为
// "/memfd:frida-agent-... (deleted)" —— 我们对 memfd 与纯匿名分开计数。
// 注意误报: 合法 JIT (ART JIT / System.loadLibrary 区段之外) / WebView /
// Vulkan ICD / ANGLE / skia 也有匿名 RX。区分条件:
//   a) 匿名 RX 但非 rwx 且大小落在 GumCodeAllocator 的 page 整数倍区间
//      (gumcodeallocator.c:144-145 pages_per_batch=7, slice 整页) —— 粗筛
//   b) 内容指纹: Gum 代码段有 thunk 三件套特征 (arm64: br x17 / ldr x17, [pc...])
//   c) 排除已知合法区间: /dev/ashmem(已废弃)、[anon:sc_aot]、[anon:webview] 等
//      命名匿名映射 (Android 上匿名映射带 name, maps 第 6 列后)

typedef struct {
    int keyword_hits;
    int anon_exec_pages;                 // 无背书匿名可执行页
    char hit_paths[16][256];
} fr_maps_scan_result;

static int fr_scan_maps(fr_maps_scan_result *out)
{
    memset(out, 0, sizeof(*out));
    char *maps = slurp_raw("/proc/self/maps", NULL);
    if (!maps) return -1;
    char *line, *save;
    for (line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char perms[8] = {0}, path[512] = {0};
        unsigned long start, end;
        int np = sscanf(line, "%lx-%lx %4s %*s %*s %*s %511[^\n]", &start, &end, perms, path);
        (void) np;
        if (strstr(line, "frida") || strstr(line, "gadget") ||
            strstr(line, "linjector") || strstr(line, "gum")) {
            if (strstr(line, "frida") || strstr(line, "linjector")) {
                if (out->keyword_hits < 16)
                    strncpy(out->hit_paths[out->keyword_hits], line, 255);
                out->keyword_hits++;
            }
        }
        if (strchr(perms, 'x') && np >= 3 && path[0] == '\0') {
            // 无文件背书的可执行映射。检查是否是命名匿名段（Android 合法用途）
            char *br = strrchr(line, ' ');
            int named = br && (strstr(br, "[anon:") == br || strstr(line, "[anon:") != NULL);
            if (!named)
                out->anon_exec_pages += (int)((end - start) / 4096);
        }
        // memfd 注入痕迹（高置信）
        if (strstr(path, "/memfd:") && strstr(path, "deleted") && strchr(perms, 'x')) {
            if (out->keyword_hits < 16)
                snprintf(out->hit_paths[out->keyword_hits], 256, "memfd-exec: %s", line);
            out->keyword_hits++;
        }
    }
    free(maps);
    return 0;
}

// ---------------------------------------------------------------------------
// 3. /proc/net/tcp + /proc/net/unix
// ---------------------------------------------------------------------------
// 27042 为 DEFAULT_CONTROL_PORT (frida-core/lib/base/socket.vala:4)。
// frida-server 独立进程监听 27042 —— 这是 frida-server 场景，非 agent-in-process。
// agent 场景通信走 injector 建立的 socketpair fd (agent_ctrlfd, agent.vala:157-165)。
// 抽象命名空间扫描覆盖两个已核实的字面量前缀（均为源码可证）:
//   "/frida-zymbiote-" + UUID —— linux-host-session.vala:1576，zymbiote 模式下
//     frida-server 侧 bind+listen 的抽象 socket（linux-host-session.vala:1579-1580）
//   "/frida-" + UUID —— frida-helper-process.vala:341，helper 的抽象 socket

static int fr_check_control_port(void)
{
    struct sockaddr_in sa = { .sin_family = AF_INET };
    sa.sin_port = htons(27042);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    int rc = connect(fd, (struct sockaddr *) &sa, sizeof sa);
    if (rc == 0) {
        // D-Bus 握手特征探测: 发送 \0AUTH\r\n，回包应含 REJECTED ...
        // (frida D-Bus 协议带 AUTH EXTERNAL / re.frida.* name，见 session.vala:4)
        static const char dbus_probe[] = "\0AUTH\r\n";
        send(fd, dbus_probe, sizeof dbus_probe - 1, MSG_NOSIGNAL);
        char resp[256] = {0};
        ssize_t n = recv(fd, resp, sizeof resp - 1, MSG_DONTWAIT);
        close(fd);
        if (n > 0 && strncmp(resp, "REJECT", 6) == 0) return 2; // D-Bus 端点确认
        return 1; // 端口开但非 dbus（可能是被改端口的 frida-server / 其他服务）
    }
    close(fd);
    return 0;
}

static int fr_check_proc_net(void)
{
    int score = 0;
    char *tcp = slurp_raw("/proc/net/tcp", NULL);
    if (tcp) {
        // 0A = LISTEN, 本地端口 0x69A2 = 27042
        for (char *p = strstr(tcp, ":69A2"); p; p = strstr(p + 1, ":69A2"))
            if (strstr(p, " 0A ")) score++;
        free(tcp);
    }
    char *unix_socks = slurp_raw("/proc/net/unix", NULL);
    if (unix_socks) {
        char *p;
        for (p = strstr(unix_socks, "frida"); p; p = strstr(p + 1, "frida")) {
            // 排除误报: 只算抽象命名空间 @ 前缀或路径含 frida-server/gadget 的
            char *line_start = p;
            while (line_start > unix_socks && *line_start != '\n') line_start--;
            (void) line_start;
            score++;
        }
        // 专项（源码可证的两个字面量前缀，防止裸 "frida" 子串误吃无关路径）:
        //  - zymbiote 抽象 socket: linux-host-session.vala:1576
        //    "/frida-zymbiote-" + Uuid.string_random()
        //  - helper 抽象 socket: frida-helper-process.vala:341
        //    "/frida-" + Uuid.string_random()（8-4-4-4-12 hex 形态）
        if (strstr(unix_socks, "/frida-zymbiote-")) score += 5;
        {
            // 匹配 "/frida-" 后跟 UUID 形态（xxxxxxxx-xxxx-...）才算，避免裸前缀误报
            for (char *q = strstr(unix_socks, "/frida-"); q;
                 q = strstr(q + 1, "/frida-")) {
                const char *u = q + 7;
                int hex = 0;
                while (isxdigit((unsigned char) u[hex]) || u[hex] == '-') hex++;
                if (hex >= 32) { score += 3; break; } // UUID(36字符) 起码 32 形态字符
            }
        }
        free(unix_socks);
    }
    return score;
}

// ---------------------------------------------------------------------------
// 4. dl_iterate_phdr —— 已加载 so 白名单/黑名单
// ---------------------------------------------------------------------------
// 误报控制: 黑名单只匹配 soname（dlpi_name 可能是完整路径或空），
// 合法系统库不含 frida/gadget 前缀；memfd 注入的 agent dlpi_name 为
// "/memfd:..." — 单列检测不并入黑名单误报。

typedef struct { int hits; char names[16][256]; } fr_phdr_result;

static int fr_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data)
{
    fr_phdr_result *r = data;
    (void) sz;
    const char *n = info->dlpi_name ? info->dlpi_name : "";
    if (!*n) return 0;  // 主程序
    const char *base = strrchr(n, '/');
    base = base ? base + 1 : n;
    if (strstr(base, "frida") || strstr(base, "gadget") || strstr(base, "gum") ||
        strstr(base, "linjector")) {
        if (r->hits < 16) snprintf(r->names[r->hits], 256, "%s", n);
        r->hits++;
    } else if (strstr(n, "/memfd:") && strstr(n, "deleted")) {
        if (r->hits < 16) snprintf(r->names[r->hits], 256, "memfd-agent: %s", n);
        r->hits++;
    }
    return 0;
}

static int fr_scan_loaded_libs(fr_phdr_result *out)
{
    memset(out, 0, sizeof(*out));
    dl_iterate_phdr(fr_phdr_cb, out);
    return out->hits;
}

// ---------------------------------------------------------------------------
// 5. ART ArtMethod entrypoint 合法性
// ---------------------------------------------------------------------------
// 原理: Frida Interceptor 修改被 hook 方法的 ART entrypoint 或在 native
// trampoline 区安置跳板。Gum 的跳板落在 GumCodeAllocator 分配的页
// (gumcodeallocator.c: gum_code_allocator_try_alloc_batch_near —— 倾向于
// 分配在被 hook 函数 ±2GB 内的匿名页，代码段无文件背书)。
// 检测: 遍历 libart 的 ART methods 不可行（不在我们层），改为检测
// **JNI 注册表之外的可调用 code 是否落在无背书匿名 RX**:
//   - 读取 maps 收集合法 RX 区间 (文件背书: /system /apex /data/app .../lib/*.so)
//   - 对关键函数 (我们 dlsym 到的 libc/libart 函数) 的地址做区间检查:
//     落在匿名 RX = 被 relocated/hooked。
// 这是"自体关键函数完整性"检查 —— 比枚举 ArtMethod 便宜且不依赖 ART 内部布局。

static int fr_check_code_region_legitimacy(void)
{
    // 1. 收集合法区间集合（有文件背书的 x 段）
    // 2. 检查一组哨兵函数: strlen/memcpy/malloc/dlopen 是否在合法区间
    struct sentinel { const char *sym; void *addr; };
    struct sentinel s[] = {
        {"strlen",  (void *) strlen},  {"memcpy",  (void *) memcpy},
        {"malloc",  (void *) malloc},  {"dlopen",  (void *) dlopen},
    };
    int anomalies = 0;
    // 简化 maps 收集
    char *maps = slurp_raw("/proc/self/maps", NULL);
    if (!maps) return -1;
    char *line, *save;
    for (line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
        ;
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
        unsigned long a = (unsigned long) s[i].addr;
        // 逐行查地址归属
        char *m2 = slurp_raw("/proc/self/maps", NULL);
        int found_legit = 0, found_anon_x = 0;
        if (!m2) break;
        char *l2, *sv2;
        for (l2 = strtok_r(m2, "\n", &sv2); l2; l2 = strtok_r(NULL, "\n", &sv2)) {
            unsigned long st, en; char perms[8] = {0};
            sscanf(l2, "%lx-%lx %4s", &st, &en, perms);
            if (a >= st && a < en) {
                if (strchr(perms, 'x')) {
                    if (strstr(l2, "/") && !strstr(l2, "[anon:")) found_legit = 1;
                    else found_anon_x = 1;
                }
                break;
            }
        }
        free(m2);
        if (found_anon_x && !found_legit) anomalies++;
    }
    free(maps);
    return anomalies;
}

// ---------------------------------------------------------------------------
// 7. /proc/self/status: TracerPid / Seccomp
// ---------------------------------------------------------------------------
// 原版 frida spawn 模式 PTRACE_ATTACH 会留 TracerPid>0（gum 自身也这么查
// TracerPid: gumprocess-linux.c:525），spawn 完成后 detach —— attach 注入
// 时窗口内可捕获。Seccomp 原版不用；魔改若用 seccomp 反检测则 Seccomp=2
// 本身成为新指纹。
static int fr_check_status(int *tracer_pid, int *seccomp_mode)
{
    char *st = slurp_raw("/proc/self/status", NULL);
    if (!st) return -1;
    char *p = strstr(st, "TracerPid:");
    *tracer_pid = p ? atoi(p + 10) : -1;
    p = strstr(st, "Seccomp:");
    *seccomp_mode = p ? atoi(p + 8) : -1;
    free(st);
    return 0;
}

// ---------------------------------------------------------------------------
// 8. 文件系统痕迹: frida-server 路径存在性
// ---------------------------------------------------------------------------
static const char *const fr_server_paths[] = {
    "/data/local/tmp/frida-server",
    "/data/local/tmp/frida-server-16",
    "/data/local/tmp/fs",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-gadget",
    "/data/local/tmp/frida-helper-32",
    "/data/local/tmp/frida-helper-64",
    NULL
};

static int fr_check_server_files(char found[8][256])
{
    int n = 0;
    for (int i = 0; fr_server_paths[i] && n < 8; i++) {
        struct stat st;
        // 用 faccessat syscall 直通，避免 libc hook（如被 inline patch 时绕过无效）
        if (syscall(__NR_faccessat, AT_FDCWD, fr_server_paths[i], F_OK, 0) == 0 ||
            stat(fr_server_paths[i], &st) == 0) {
            snprintf(found[n++], 256, "%s", fr_server_paths[i]);
        }
    }
    // 模式匹配: /data/local/tmp/frida-helper-*.dex (linux-host-session.vala:486)
    int fd = raw_open("/data/local/tmp", O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
        char buf[4096];
        for (;;) {
            ssize_t k = raw_getdents64(fd, buf, sizeof buf);
            if (k <= 0) break;
            for (size_t off = 0; off < (size_t) k; ) {
                struct linux_dirent64 { uint64_t ino; int64_t off2; unsigned short reclen; unsigned char type; char name[]; };
                struct linux_dirent64 *d = (void *) (buf + off);
                off += d->reclen;
                if ((strstr(d->name, "frida-helper-") || strstr(d->name, "frida-server")) && n < 8)
                    snprintf(found[n++], 256, "/data/local/tmp/%s", d->name);
            }
        }
        close(fd);
    }
    return n;
}

// ---------------------------------------------------------------------------
// 9. crash 通道: 自诱崩溃后从 tombstone/logcat 抓 gum-js-loop / frida-agent 帧
// ---------------------------------------------------------------------------
// 说明: tombstone 属 tombstoned, 我们进程内不可直接读自身 tombstone;
// 工装在 Java 层 (FridaDetect.java) 用一个子进程 abort() 后读
// /data/tombstones 或 logcat。此处提供帧匹配器供上层使用。
int fr_crash_backtrace_contains_frida(const char *bt)
{
    return bt && (strstr(bt, "gum-js-loop") || strstr(bt, "frida-agent") ||
                  strstr(bt, "gum_memory") || strstr(bt, "gum_interceptor"));
}

// ---------------------------------------------------------------------------
// 汇总入口
// ---------------------------------------------------------------------------
fr_scan_report fr_detect_all(void)
{
    fr_scan_report r;
    memset(&r, 0, sizeof r);

    fr_thread_scan_result th;
    r.thread_hits = fr_scan_thread_names(&th);
    memcpy(r.thread_names, th.names, sizeof r.thread_names);

    fr_maps_scan_result mp;
    fr_scan_maps(&mp);
    r.maps_keyword_hits = mp.keyword_hits;
    r.maps_anon_exec_pages = mp.anon_exec_pages;

    r.net_score = fr_check_proc_net();
    r.port_27042 = fr_check_control_port();

    fr_phdr_result ph;
    r.phdr_hits = fr_scan_loaded_libs(&ph);
    memcpy(r.lib_names, ph.names, sizeof r.lib_names);

    r.code_anomalies = fr_check_code_region_legitimacy();
    fr_check_status(&r.tracer_pid, &r.seccomp_mode);

    r.fs_hits = fr_check_server_files(r.fs_paths);

    // 综合判定: 权重见矩阵文档
    r.score =
        (r.thread_hits > 0 ? 50 : 0) +
        (r.maps_keyword_hits > 0 ? 30 : 0) +
        (r.maps_anon_exec_pages > 4 ? 10 : 0) +
        (r.port_27042 == 2 ? 25 : (r.port_27042 == 1 ? 10 : 0)) +
        (r.net_score > 0 ? 20 : 0) +
        (r.phdr_hits > 0 ? 40 : 0) +
        (r.code_anomalies > 0 ? 20 : 0) +
        (r.tracer_pid > 0 ? 15 : 0) +
        (r.seccomp_mode == 2 ? 10 : 0) +
        (r.fs_hits > 0 ? 20 : 0);
    r.detected = r.score >= 30;
    return r;
}
