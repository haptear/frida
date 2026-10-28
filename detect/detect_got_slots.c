// detect_got_slots.c — 检测项 #11: GOT 导入槽劫持检测
// 纯静态逻辑，不依赖设备/构建。
//
// 判据（源码可证）:
//  ThreadCountCloaker 不碰 libc .text，而是改写 libart 的 GOT 导入槽:
//  frida-core/lib/payload/cloak.vala:62-82 —— art.enumerate_imports 取
//  `art::GetOsThreadStat`（符号 _ZN3art15GetOsThreadStatEiPcm/Pcj）与 `read`
//  的 slot（imp.slot），update_slot 把 *slot 改指自家函数（on_get_os_thread_stat /
//  on_read，cloak.vala:107-141）。GOT 落在 rw- 数据页 —— .text 序言比对（#10）
//  与匿名 RX 检测（#2b/#5）对它全部失明。
//
// 本检测遍历目标 so 的 .rela.plt/.rela.dyn（R_*_JUMP_SLOT / R_*_GLOB_DAT），
// 取 *slot 与 dlsym 解析出的"真值"比对，不等即疑似 GOT 劫持。
//
// 难点 (a)(b)(c) 与误报控制 → 见 DETECT_MATRIX.md 检测项 #11 详述节。

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <elf.h>

// ---------------------------------------------------------------------------
// raw read helpers（与 frida_detect.c 同款，避免 libc 依赖面）
// ---------------------------------------------------------------------------
static int raw_open(const char *p) { return (int) syscall(__NR_openat, AT_FDCWD, p, O_RDONLY | O_CLOEXEC, 0); }
static ssize_t raw_read(int fd, void *b, size_t n) { return syscall(__NR_read, fd, b, n); }

static uint8_t *read_file_all(const char *path, size_t *out_sz)
{
    int fd = raw_open(path);
    if (fd < 0) return NULL;
    size_t cap = 1 << 20, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 65536 > cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) { close(fd); return NULL; } }
        ssize_t n = raw_read(fd, buf + len, cap - len);
        if (n <= 0) break;
        len += (size_t) n;
    }
    close(fd);
    *out_sz = len;
    return buf;
}

// ---------------------------------------------------------------------------
// 模块定位: dl_iterate_phdr 找 soname，返回 {加载基址, dlpi_name}
// ---------------------------------------------------------------------------
typedef struct {
    const char *want;      // soname 子串，如 "libart.so"
    uintptr_t base;
    const char *path;
    int found;
} find_mod_t;

static int find_mod_cb(struct dl_phdr_info *info, size_t sz, void *data)
{
    find_mod_t *f = data;
    (void) sz;
    const char *n = info->dlpi_name ? info->dlpi_name : "";
    const char *base = strrchr(n, '/');
    base = base ? base + 1 : n;
    if (strstr(base, f->want)) {
        f->base = (uintptr_t) info->dlpi_addr;
        f->path = n;
        f->found = 1;
        return 1;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// (a) FULL RELRO 静态判据（ELF 头侧，不执行任何东西）:
//   readelf -l: 存在 GNU_RELRO segment，且其范围**覆盖** .got 与 .got.plt
//   readelf -d: 同时含 DT_BIND_NOW（或 DF_BIND_NOW / DF_1_NOW flag）
//   两者齐备 = FULL RELRO（加载后 linker mprotect .got 只读）；
//   只有 GNU_RELRO 无 BIND_NOW = PARTIAL（.got.plt 仍可写，lazy binding 生效）。
//   bionic 的 linker 实现口径与 glibc 一致（linker 置 RELRO 段 PROT_READ）。
// ---------------------------------------------------------------------------
typedef struct {
    int has_relro;        // 有 GNU_RELRO segment
    int has_bind_now;     // DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW
    uint64_t relro_start, relro_end;
    uint64_t got_vaddr, got_size;      // .got（含 .got.plt 合并视图）
    int full_relro;       // has_relro && has_bind_now && relro 覆盖 got
} relro_info_t;

static void analyze_relro(const Elf64_Ehdr *eh, relro_info_t *ri)
{
    memset(ri, 0, sizeof *ri);
    const Elf64_Phdr *ph = (const void *) ((const char *) eh + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_GNU_RELRO) {
            ri->has_relro = 1;
            ri->relro_start = ph[i].p_vaddr;
            ri->relro_end = ph[i].p_vaddr + ph[i].p_memsz;
        }
    }
    const Elf64_Dyn *dyn = NULL;
    const Elf64_Shdr *sh = (const void *) ((const char *) eh + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++)
        if (sh[i].sh_type == SHT_DYNAMIC) { dyn = (const void *) ((const char *) eh + sh[i].sh_offset); break; }
    if (dyn)
        for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++)
            if (d->d_tag == DT_BIND_NOW) ri->has_bind_now = 1;
            else if (d->d_tag == DT_FLAGS && (d->d_un.d_val & DF_BIND_NOW)) ri->has_bind_now = 1;
            else if (d->d_tag == DT_FLAGS_1 && (d->d_un.d_val & DF_1_NOW)) ri->has_bind_now = 1;
    // .got 区间（section 名 .got 或 .got.plt，取并集近似）
    const char *shstr = (const char *) eh + sh[eh->e_shstrndx].sh_offset;
    for (int i = 0; i < eh->e_shnum; i++) {
        const char *nm = shstr + sh[i].sh_name;
        if (!strcmp(nm, ".got") || !strcmp(nm, ".got.plt")) {
            if (ri->got_size == 0) { ri->got_vaddr = sh[i].sh_addr; ri->got_size = sh[i].sh_size; }
            else {
                uint64_t lo = ri->got_vaddr < sh[i].sh_addr ? ri->got_vaddr : sh[i].sh_addr;
                uint64_t hi = ri->got_vaddr + ri->got_size > sh[i].sh_addr + sh[i].sh_size
                            ? ri->got_vaddr + ri->got_size : sh[i].sh_addr + sh[i].sh_size;
                ri->got_vaddr = lo; ri->got_size = hi - lo;
            }
        }
    }
    ri->full_relro = ri->has_relro && ri->has_bind_now &&
                     ri->got_vaddr >= ri->relro_start &&
                     ri->got_vaddr + ri->got_size <= ri->relro_end;
}

// ---------------------------------------------------------------------------
// (b) 只读 GOT 的判据稳定性:
//   RELRO 只影响**写**（linker reloc 后 mprotect PROT_READ）。读 *slot
//   永远合法（映射仍 PROT_READ）。Frida 改槽必须先 mprotect rw 再改再还原，
//   该 mprotect 会在内核留痕（可另列检测），但 slot 比对本身完全稳定 ——
//   无论读写状态，被改过的槽在任意时刻读出来都是劫持地址。
//   （例外：改完又 mprotect 回只读后，地址仍在 —— 判据不变。）
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// (c) lazy binding 未解析槽的误报规避:
//   PARTIAL RELRO + lazy binding 时，JUMP_SLOT 未解析的 *slot 指向
//   PLT 桩第 2 条指令（push index / 跳 resolver），不是目标函数 ——
//   裸比对必然误报。规避:
//     1) 只对**已解析**的槽比对: 若 *slot 落在本模块自身 PT_LOAD(EXEC) 内
//        → 指向 PLT 桩 → unresolved → 跳过不判。
//     2) 更稳: 先主动调用一次目标函数（对无副作用的 read/open 类不可行）——
//        不采用；只用 (1) 的区间判据 + GLOB_DAT（.rela.dyn，加载即解析，
//        无 lazy 问题）优先。
//   Android 实践注: 现代 bionic linker 默认对 APK 内 so 用 BIND_NOW
//   （Android 6+ 系统 so 全部 FULL RELRO），lazy 场景主要是老设备/定制 ROM。
// ---------------------------------------------------------------------------

typedef struct {
    const char *sym;
    void *slot_val;        // *slot 当前值
    void *dlsym_val;       // dlsym 解析"真值"
    const char *verdict;   // "clean"/"HIJACKED"/"unresolved-skip"/"cross-lib-skip"
} got_check_item;

typedef struct {
    int n, hijacked, clean, skipped;
    got_check_item items[64];
    relro_info_t relro;
} got_report;

// 遍历模块重定位表做槽比对。module_path: 磁盘路径（解析 symtab）;
// load_base: dlpi_addr。targets: 关注的符号名集合（NULL 结尾）。
static got_report fr_check_got_slots(const char *module_path, uintptr_t load_base,
                                     const char *const targets[])
{
    got_report rep;
    memset(&rep, 0, sizeof rep);

    size_t fsz = 0;
    uint8_t *elf = read_file_all(module_path, &fsz);
    if (!elf || fsz < sizeof(Elf64_Ehdr) || memcmp(elf, ELFMAG, 4) != 0) return rep;
    const Elf64_Ehdr *eh = (const void *) elf;
    analyze_relro(eh, &rep.relro);
    rep.relro.full_relro = rep.relro.has_relro && rep.relro.has_bind_now; // 判据(a)结论

    const Elf64_Shdr *sh = (const void *) ((const char *) eh + eh->e_shoff);
    const char *shstr = (const char *) eh + sh[eh->e_shstrndx].sh_offset;
    const Elf64_Sym *symtab = NULL; const char *strtab = NULL; size_t nsym = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *nm = shstr + sh[i].sh_name;
        if (sh[i].sh_type == SHT_DYNSYM) {
            symtab = (const void *) ((const char *) eh + sh[i].sh_offset);
            nsym = sh[i].sh_size / sizeof(Elf64_Sym);
            // 对应 SHT_STRTAB（sh_link）
            strtab = (const char *) eh + sh[sh[i].sh_link].sh_offset;
        }
    }
    if (!symtab) { free(elf); return rep; }

    // 模块自身可执行段范围（判 *slot 是否指向 PLT 桩 → unresolved）
    uintptr_t exec_lo = UINTPTR_MAX, exec_hi = 0;
    {
        const Elf64_Phdr *ph = (const void *) ((const char *) eh + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && (ph[i].p_flags & PF_X)) {
                uintptr_t lo = load_base + ph[i].p_vaddr;
                uintptr_t hi = lo + ph[i].p_memsz;
                if (lo < exec_lo) exec_lo = lo;
                if (hi > exec_hi) exec_hi = hi;
            }
    }

    for (int i = 0; i < eh->e_shnum && rep.n < 64; i++) {
        const char *nm = shstr + sh[i].sh_name;
        int is_rela = sh[i].sh_type == SHT_RELA;
        if (!is_rela) continue;
        int is_plt = strstr(nm, ".rela.plt") != NULL;
        // .rela.plt = JUMP_SLOT(lazy 风险); .rela.dyn 的 GLOB_DAT 加载即解析
        size_t cnt = sh[i].sh_size / sizeof(Elf64_Rela);
        const Elf64_Rela *rel = (const void *) ((const char *) eh + sh[i].sh_offset);
        for (size_t k = 0; k < cnt && rep.n < 64; k++) {
            uint32_t sym_idx = ELF64_R_SYM(rel[k].r_info);
            uint32_t type = ELF64_R_TYPE(rel[k].r_info);
            if (type != R_AARCH64_JUMP_SLOT && type != R_AARCH64_GLOB_DAT &&
                type != R_AARCH64_IRELATIVE)  // arm64
                continue;
            if (type == R_AARCH64_IRELATIVE) continue;  // IFUNC 内部，跳过（见误报控制）
            if (sym_idx == 0 || sym_idx >= nsym) continue;
            const char *sym_name = strtab + symtab[sym_idx].st_name;
            if (!sym_name[0]) continue;

            int wanted = 0;
            for (int t = 0; targets[t]; t++)
                if (!strcmp(sym_name, targets[t])) { wanted = 1; break; }
            if (!wanted) continue;

            void **slot = (void **) (load_base + rel[k].r_offset);
            got_check_item *it = &rep.items[rep.n++];
            it->sym = sym_name;
            it->slot_val = *slot;   // (b): 只读也能读，判据稳定

            // (c) lazy unresolved: *slot 指向本模块 PLT 桩 → 跳过
            if ((uintptr_t) it->slot_val >= exec_lo && (uintptr_t) it->slot_val < exec_hi) {
                it->verdict = is_plt ? "unresolved-skip" : "self-skip";
                rep.skipped++;
                continue;
            }

            // 真值: dlsym 全局解析（RTLD_DEFAULT 会命中**最新**加载的定义 —— 见误报控制）
            void *real = dlsym(RTLD_DEFAULT, sym_name);
            it->dlsym_val = real;
            if (!real) { it->verdict = "no-sym"; rep.skipped++; continue; }

            if (it->slot_val == real) { it->verdict = "clean"; rep.clean++; }
            else {
                it->verdict = "HIJACKED";
                rep.hijacked++;
            }
        }
    }
    free(elf);
    return rep;
}

// 顶层入口: 检查 libart.so 的 read / GetOsThreadStat 槽（cloak.vala:62-82 的目标）
// 其次 libc / libc++_shared 的 read/open/openat/pread64。
got_report fr_detect_got_hijack(void)
{
    static const char *const kArtTargets[] = {
        "read",
        "_ZN3art15GetOsThreadStatEiPcm",
        "_ZN3art15GetOsThreadStatEiPcj",
        NULL
    };
    find_mod_t fm = { .want = "libart.so" };
    dl_iterate_phdr(find_mod_cb, &fm);
    if (fm.found)
        return fr_check_got_slots(fm.path, fm.base, kArtTargets);
    // libart 未加载（纯 native 进程）→ 退化为 libc 自查（GOT 无cloak，但留接口）
    static const char *const kLibcTargets[] = { "read", "open", "openat", "pread64", NULL };
    find_mod_t fl = { .want = "libc.so" };
    dl_iterate_phdr(find_mod_cb, &fl);
    if (fl.found)
        return fr_check_got_slots(fl.path, fl.base, kLibcTargets);
    got_report empty; memset(&empty, 0, sizeof empty);
    return empty;
}
