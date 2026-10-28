// detect_libc_prologue.c — 检测项 #10: libc 导出函数序言完整性比对
// 纯静态比对逻辑：进程内函数前 N 字节 vs 磁盘 libc 同偏移字节。
// 不依赖任何设备 —— 判据与误报分析见 DETECT_MATRIX.md 第 10 节。
//
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// 原理锚点（源码可证）:
//  - cloak 的 DirListCloaker 挂 libc 的 opendir/closedir/readdir/readdir64/
//    readdir_r/readdir64_r 六个导出 —— frida-core/lib/payload/cloak.vala:257-284
//    (实例化: agent.vala:1123-1125)
//  - ThreadCountCloaker 挂 libc 的 read（cloak.vala:263 附近, on_read:123）
//  - Interceptor arm64 重定向形态 —— gum/backend-arm64/guminterceptor-arm64.c:
//    1205-1246: 覆写目标函数序言为
//      4B:  B imm                        (单条分支)
//      8B:  ADRP Xn, target; BR Xn
//     16B:  LDR Xn, =target; BR Xn       (FULL_REDIRECT, scratch reg)
//    bionic libc 函数被 attach 时序言被改写为上述三种形态之一。
//  - arm32 形态在 gum/backend-arm/guminterceptor-arm.c（B/相对跳转 + LDR PC），
//    本文件按 arm64 为主，arm32 判据给出等价说明。
// ---------------------------------------------------------------------------

#define PROLOGUE_BYTES 16   // 覆盖最大 FULL_REDIRECT (16B)

// 哨兵名单：cloak 必挂的 6 个 + 我们 maps 清洗将来要 hook 的 4 个
static const char *const kSentinels[] = {
    "opendir", "closedir", "readdir", "readdir64",
    "readdir_r", "readdir64_r",
    "open", "openat", "read", "pread64",
    NULL
};

// arm64 redirect 常量:
//  LDR Xn, #8 (imm=0): 58 00 00 58 (n=0) … 58 00 1F 58 无效; 实际
//  guminterceptor 写 LDR Xn, =on_enter 为 4 字节 LDR literal + 8 字节
//  absolute address + BR Xn (00 02 1F D6)。
//  我们不做字节级模式匹配（太脆），做「进程内 vs 磁盘」逐字节 diff ——
//  diff > 0 即序言被覆写，模式仅用于分类报告。

typedef struct {
    const char *sym;
    int  diff_bytes;              // 前 16B 中不匹配字节数
    uint8_t mem[PROLOGUE_BYTES];
    uint8_t disk[PROLOGUE_BYTES];
    const char *verdict;          // "clean" / "HOOKED" / "alias?" / "n/a"
} fr_prologue_check;

typedef struct {
    int n, hooked, clean, na;
    fr_prologue_check items[16];
} fr_prologue_report;

// ---------------------------------------------------------------------------
// 定位磁盘 libc: 通过 /proc/self/maps 找到 libc 路径与 bias（不依赖 dladdr，
// 避免 dlpi_name 为空的坑；maps 解析本身用 raw open/read）
// ---------------------------------------------------------------------------
static char *slurp_raw(const char *path, size_t *out_len)
{
    int fd = (int) syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return NULL;
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 1024 > cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) { close(fd); return NULL; } }
        ssize_t n = (ssize_t) syscall(__NR_read, fd, buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t) n;
    }
    close(fd);
    if (out_len) *out_len = len;
    buf[len] = 0;
    return buf;
}

// 解析磁盘 ELF 的 program headers，把进程内虚拟地址换算为文件偏移。
// 只认 PT_LOAD。返回 0 成功。
static int vaddr_to_file_offset(const Elf64_Ehdr *eh, uint64_t vaddr,
                                uint64_t *out_off, uint64_t *out_filesz)
{
    const Elf64_Phdr *ph = (const void *) ((const char *) eh + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD &&
            vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_filesz) {
            *out_off = ph[i].p_offset + (vaddr - ph[i].p_vaddr);
            *out_filesz = ph[i].p_filesz;
            return 0;
        }
    }
    return -1;
}

// ELF64 假设 arm64；arm32 需 Elf32_*（编译时按 ABI 选择，见 build.md）
fr_prologue_report fr_check_libc_prologue(void)
{
    fr_prologue_report rep;
    memset(&rep, 0, sizeof rep);

    // 1. 从 maps 找 libc.so 的基址与磁盘路径
    char *maps = slurp_raw("/proc/self/maps", NULL);
    if (!maps) return rep;
    uint64_t libc_base = 0;
    char libc_path[256] = {0};
    char *line, *save;
    for (line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strstr(line, "/libc.so")) {
            sscanf(line, "%lx-", (unsigned long *) &libc_base);
            char *p = strchr(line, '/');
            if (p) { strncpy(libc_path, p, sizeof libc_path - 1);
                     libc_path[strcspn(libc_path, "\n")] = 0; }
            break;
        }
    }
    free(maps);
    if (!libc_base || !libc_path[0]) return rep;

    // 2. mmap 磁盘 libc（只读）
    int fd = (int) syscall(__NR_openat, AT_FDCWD, libc_path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return rep;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return rep; }
    size_t fsz = (size_t) st.st_size;
    uint8_t *elf = malloc(fsz);
    if (!elf) { close(fd); return rep; }
    size_t got = 0;
    while (got < fsz) {
        ssize_t n = (ssize_t) syscall(__NR_read, fd, elf + got, fsz - got);
        if (n <= 0) break;
        got += (size_t) n;
    }
    close(fd);
    if (got < sizeof(Elf64_Ehdr) || memcmp(elf, ELFMAG, 4) != 0) { free(elf); return rep; }
    const Elf64_Ehdr *eh = (const void *) elf;

    // 3. 逐哨兵: dlsym 进程内地址 → 换算磁盘偏移 → 比对前 16 字节
    for (int i = 0; kSentinels[i] && rep.n < 16; i++) {
        fr_prologue_check *it = &rep.items[rep.n++];
        it->sym = kSentinels[i];

        void *addr = dlsym(RTLD_DEFAULT, kSentinels[i]);
        if (!addr) { it->verdict = "n/a"; rep.na++; continue; }

        uint64_t vaddr = (uint64_t)(uintptr_t) addr - libc_base;
        uint64_t off = 0, filesz = 0;
        if (vaddr_to_file_offset(eh, vaddr, &off, &filesz) != 0 ||
            off + PROLOGUE_BYTES > fsz) {
            // 地址不在 libc 的 PT_LOAD 文件区 —— 别名/IFUNC resolver/其它库实现
            it->verdict = "alias?";
            rep.na++;
            continue;
        }
        memcpy(it->mem, addr, PROLOGUE_BYTES);
        memcpy(it->disk, elf + off, PROLOGUE_BYTES);
        it->diff_bytes = 0;
        for (int b = 0; b < PROLOGUE_BYTES; b++)
            if (it->mem[b] != it->disk[b]) it->diff_bytes++;

        if (it->diff_bytes == 0) { it->verdict = "clean"; rep.clean++; }
        else { it->verdict = "HOOKED"; rep.hooked++; }
    }
    free(elf);
    return rep;
}
