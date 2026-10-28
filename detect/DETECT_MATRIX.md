# Frida 检测矩阵 — 原版命中概率 / 误报 / 对抗难度

> **范围声明**：本轮为纯分析轮次。本文档中所有结论分两类：**源码可证**（给出
> 文件:行，可直接在 `D:\tools\apk-reverses\frida-mg` 对上）与 **待实测**（需设备/
> 动态验证，本轮未执行，标注 `待实测`）。不调用模拟器、不构建、不部署。
>
> 证据基准：`D:\tools\apk-reverses\frida-mg`（frida monorepo，subprojects/frida-gum + frida-core）。
> 检测实现见同目录 C/Java 代码。

## 矩阵总表

| # | 检测项 | 读取的 syscall / API | 原版 Frida 命中概率 | 误报风险 | 对抗难度（魔改侧） |
|---|--------|----------------------|---------------------|----------|--------------------|
| 1 | 线程名 `gum-js-loop` 等枚举 | `getdents64`(/proc/self/task) + `openat`/`read`(comm)；`pthread_getname_np` | **高**（spawn+attach 场景 ~100%，脚本运行期必然存在 JS 线程） | 低 | **低**——改名即可（一行），但改名会破坏 gum 内部对该名字的依赖吗？不依赖，纯展示。实际最易绕 |
| 2a | maps 关键词 frida/gadget/linjector/gum | `openat`+`read` (/proc/self/maps) | **中高**——agent 以 memfd 注入时路径是 `/memfd:... (deleted)`，不含 "frida" 字面（linjector.vala:253-261）；但 dlpi_name 与部分 maps 行仍可见 | 低 | 中——需改注入器名字与 memfd 名 |
| 2b | 有 x 权限却无文件背书的匿名映射 | 同上 + maps 解析 | **高**——Interceptor 跳板由 GumCodeAllocator 分配匿名 RX 页（gumcodeallocator.c:144-145, guminterceptor.c:295 commit） | **高（JIT/WebView/Vulkan）**——见误报控制 | 高——需把跳板藏进合法区段或 hook 我们的读取 |
| 3a | 127.0.0.1:27042 探活 + D-Bus 握手 | `socket`+`connect`+`send`+`recv` | **仅 frida-server 场景高**；agent 模式（in-process）不走 27042。默认端口常量 socket.vala:4 | 低（极少数 App 自用 27042） | **极低**——`-l` 改端口即绕 |
| 3b | /proc/net/tcp + /proc/net/unix（抽象 socket） | `openat`+`read` | **低**——in-process agent 用 injector socketpair fd（agent.vala:157-165 agent_ctrlfd），非监听 socket；zymbiote 模式有 `/frida-zymbiote-*` 抽象 socket（linux-host-session.vala:1577-1578） | 中（unix 表里 grep "frida" 会撞到无关路径） | 中 |
| 4 | dl_iterate_phdr soname 黑名单 | `dl_iterate_phdr`（内部走 linker 的 soinfo 链） | **高**——注入的 frida-agent.so 出现在 phdr 链，dlpi_name 为 memfd 路径 | 低 | 高——需从 linker soinfo 链摘除（linker namespace 技巧），或改 soname |
| 5 | ArtMethod entrypoint / 关键函数落在匿名 RX | maps 区间归属性检查 + `dlsym` 哨兵 | **高**——被 hook 的方法 entrypoint 指向 Gum trampoline（匿名 RX） | **中高**——ART JIT 区也匿名，见误报控制 | 高——GumCodeAllocator 已尽量分配在目标 ±2GB（gumcodeallocator.c:105 try_alloc_batch_near），魔改可进一步贴近合法区段 |
| 6a | /proc/self/status TracerPid | `openat`+`read` | **窗口性**——linjector 用 PTRACE_ATTACH 注入（frida-helper-backend.vala:1915 `_ptrace(req, tid...)`），注入完 detach 后 TracerPid=0 | 低 | 已天然规避（detach 即清） |
| 6b | Seccomp 字段 | 同上 | **零**（原版不用 seccomp） | 零 | 魔改若上 seccomp 反检测，Seccomp=2 反成新指纹 |
| 7 | /data/local/tmp 下 frida-server / frida-helper-* 存在性 | `faccessat` / `getdents64` | frida-server 场景 **高**；注入模式下 AndroidHelper 落盘 `frida-helper-<uuid>.dex`（linux-host-session.vala:486，用完 unlink）——**瞬时窗口** | 低 | 低——移动/改名即绕 |
| 8 | 自崩栈/tombstone 中 gum-js-loop / frida-agent 帧 | SIGSEGV 后 debuggerd 输出全线程 backtrace | **中**（源码可证机制；实测频率 `待实测`）——debuggerd dump 列出所有线程名与映射，frida 线程与 agent 映射在崩溃瞬间可见（ThreadListCloaker 对 debuggerd 无效——它 hook 的是本进程 readdir，debuggerd 读 /proc/<pid> 走自己进程） | 低 | 高——需在崩溃通道上同步隐藏 |
| 10 | libc 导出序言完整性比对（进程内存 vs 磁盘） | `dlsym` 取进程内地址 + raw `openat`/`read` 读磁盘 libc + PT_LOAD 换算 | **高**（源码可证存在性；实测命中率 `待实测`）——cloak 必挂 libc 的 opendir/closedir/readdir/readdir64/readdir_r/readdir64_r 六导出（cloak.vala:257-284，实例化 agent.vala:1123-1125），ThreadCountCloaker 另挂 `read`（cloak.vala:63-77）——序言被 Interceptor 覆写为 4/8/16B 重定向（guminterceptor-arm64.c:1205-1246）。**不依赖任何 "frida" 字样，改名躲不掉** | **中（见 #10 误报分析：PLT/IFUNC/别名）** | 高——魔改要么不用 Interceptor（自写 inline patch 每个位置一个性化化），要么把磁盘比对通路也 hook 掉（但 hook 我们的 raw openat/read 又会留下新的序言伤痕，递归利好检测方） |

## 误报控制（每项的区分条件）

### 2b/5 匿名可执行映射 —— 最大的误报源
合法来源：ART JIT cache（`[anon:dalvik-jit-code-cache*` 等命名匿名段）、
WebView/V8（`[anon:webview-*`）、Vulkan ICD shader cache、ANGLE、系统 ShaderCache。
**区分条件（三层）**：
1. **命名排除**：Android maps 的纯匿名页可有 `[anon:...]` 标签——实现里跳过带
   `[anon:` 前缀的行；ART JIT/Vulkan 都是命名匿名段。
2. **归属校验**：对**我们 dlsym 到的已知函数地址**做区间归属检查（哨兵法），
   只报"已知函数被挪出文件背书区段"，而不是盲目报所有匿名 RX——
   JIT 页里不应有 libc 的 strlen/malloc/dlopen。
3. **尺寸指纹**：GumCodeAllocator 按固定 batch（pages_per_batch=7，
   gumcodeallocator.c:144）分配整页倍数 RX 区，且倾向 ±2GB 内簇状分布；
   实现（frida_detect.c）只对 >4 匿名可执行页起评，需配 1/2 中其它证据共振才计入判定。

### 1 线程名
`gmain` 在使用 GLib 的 App 自身也会出现 —— 实现里 `gmain`/`pool-*` 单独命中
不置 detected，需与 `gum-js-loop`/`frida-*` 等专属名共振。

### 3b /proc/net/unix
命中需限定为两个**源码可证**的字面量前缀（裸 "frida" 子串会误吃无关路径）:
- `/frida-zymbiote-` + UUID —— `linux-host-session.vala:1576`
  （zymbiote 模式下 frida-server 侧 bind+listen 的抽象 socket，:1579-1580）
- `/frida-` + UUID 形态（8-4-4-4-12 hex）—— `frida-helper-process.vala:341`
  （helper 抽象 socket；实现里用 UUID 形态校验而非裸前缀，避免误报）

**勘误记录**：上一版矩阵把 `/frida-zymbiote-` 标为 :1577（实际 :1576），且未给
helper 侧 `/frida-` + UUID 前缀。两处字面量均已在本基线源码重新核实存在，
非外部检测名单抄来的无源字面量。

### 7 /data/local/tmp 扫描
只报精确模式（`frida-server*`、`frida-helper-*`），且 frida-helper-*.dex
是短暂窗口（写入后即启动、finally unlink，linux-host-session.vala:486-504）——
单次未命中不构成排除证据，只做加分项。

## 检测项 #10 详述：libc 导出序言完整性比对（detect/detect_libc_prologue.c）

### 判据（源码可证）
1. 哨兵名单 10 个导出：cloak 六件套 opendir/closedir/readdir/readdir64/
   readdir_r/readdir64_r（cloak.vala:257-284）+ 我们 maps 清洗将来要 hook 的
   open/openat/read/pread64。
2. 进程内地址（`dlsym`）前 16 字节 vs 磁盘 libc（maps 定位路径与基址，
   PT_LOAD vaddr→offset 换算）同偏移字节，diff > 0 → 「疑似 hook」。
3. arm64 Interceptor 覆写形态（guminterceptor-arm64.c:1205-1246）:
   - 4B: `B imm`（近跳转）
   - 8B: `ADRP Xn, target; BR Xn`
   - 16B: `LDR Xn, =target; BR Xn`（FULL_REDIRECT + scratch reg）
   实现不做字节级模式匹配（脆），只做逐字节 diff + 形态分类供报告参考。
   arm32 等价形态见 gum/backend-arm/guminterceptor-arm.c（B / LDR PC）。

### 误报分析（PLT / IFUNC / `__libc_` 别名）
- **IFUNC resolver**：bionic 字符串/内存函数多为 IFUNC，`dlsym("memcpy")`
  返回 resolver 解析后的实现地址，仍属 libc 的 PT_LOAD 文件区，磁盘比对
  成立，不是误报源。
- **别名（`__libc_read` vs `read`）**：符号表里常是同一地址（alias/weak），
  换算后仍指向 libc 文本区，diff=0，无害。若指向 libc **之外的库**（极少），
  vaddr 超出 libc PT_LOAD → 实现里判为 `alias?` 不计 hook，宁漏勿误。
- **PLT**：App 内 PLT 是 App 自己的映射，不参与比对（dlsym 返回终地址，
  已越过 PLT）。
- **加载器重定位/RELRO/CFI**：作用于 GOT/数据段，不改 .text 字节。
- **真误报残留场景**：厂商 libc 运行期自 patch（几乎不存在）；同库 inline
  hook 来自非 frida 的加固/热修框架 —— 属「泛 hook 检出」语义而非假阳性，
  报告中标「非 frida 专属证据」，与 #1/#4 共振后才归因 frida。

### 取字节方式
自测场景直接 `memcpy` 读进程内函数地址（本进程可读），不用 `process_vm_readv`。
磁盘侧用 raw openat/read，防将来 maps 清洗侧 open hook 干扰比对通路本身。

### 判定标准（`待实测`）
待授权后验证：原版 frida attach 后 fr_check_libc_prologue() 应报
readdir 系 ≥3 个 HOOKED（diff 前 4~16B 非零），未注入时全 clean。

## 原版自带的"隐身"机制与 cloak 两层对抗边界

cloak 分两层，被绕过条件不同，必须分开评估：

### 第一层：Gum 内部枚举 cloak（Gum.Cloak，进程内数据结构）
**机制**：agent 把自己的内存 range、线程 tid、fd 登记到 Gum.Cloak 全局表
（agent.vala:141 `add_range(cached_agent_range)`、cloak.vala:25 `add_thread`、
:150 `add_file_descriptor`）。只有走 **Gum 自家枚举 API**
（`gum_process_enumerate_threads/ranges` 等，内部 `gum_cloak_clip_range`，
gumcloak.h:31-35）的观察者会被过滤。
**被绕过条件**：观察者不走 Gum API（任何正常 App/检测代码——procfs、
linker、内核接口）→ 这一层对我们完全透明，**不构成对抗面**。它只骗
frida 脚本自己（脚本里 Process.enumerateThreads() 看不到 frida 自身线程）。

### 第二层：payload libc 目录/内容过滤（inline hook，实例化 agent.vala:1123-1125）
| Cloaker | hook 目标 | 行为 | 证据 |
|---|---|---|---|
| ThreadListCloaker | opendir/closedir/readdir/readdir64/readdir_r/readdir64_r（DirListCloaker 代挂） | 藏 /proc/self/task 里的 frida 线程 tid | cloak.vala:199-216, 237-284 |
| ThreadCountCloaker | libc `read` + libart `GetOsThreadStat` | 改写 /proc/self/stat 线程数字段 | cloak.vala:46-192 |
| FDListCloaker | 同 DirListCloaker | 藏 /proc/self/fd 里的 injector fifo/ctrlfd | cloak.vala:218-235 |

**被绕过条件**：
1. **raw syscall 直通**（getdents64/openat/read 直入内核）—— 完全绕过，
   hook 只在 libc 层，内核仍持真值。**代价：hook 在 libc .text 上留下序言
   伤痕** → 反向暴露给检测项 #10。
2. **外部进程视角**（debuggerd/tombstone、另一进程读 /proc/<pid>/task）——
   完全绕过，hook 只影响本进程 libc 调用。
3. **魔改删除 cloak** —— 隐身消失但 #10 的 hook 证据也没了，检测方从 #1
   （线程名）拿回命中。

### 对抗边界结论（可直接并入主报告「对抗边界」章节）
cloak 是**自勒式防御**：隐身收益（藏线程/fd/计数）与暴露代价（libc 序言
伤痕，#10）成对出现——检测方总能在「枚举通道被 hook」与「hook 留伤痕」
之间拿到至少一个命中。魔改的完整解只有放弃 Interceptor 挂 libc（自写
syscall 包装/替换 .so/内核级），成本远高于原版。

### 其余既有机制表

| 原版机制 | 证据 | 对检测工装的影响 |
|---|---|---|
| ThreadListCloaker：hook readdir 藏 `/proc/self/task` 里的 frida 线程 | frida-core/lib/payload/cloak.vala:199-216, DirListCloaker:237-284 | **必须走 getdents64 raw syscall 直通**（本实现已做）；hook 本身是 #10 的证据 |
| ThreadCountCloaker：改写 /proc/self/stat 的线程数 | cloak.vala:46-192（hook `read` + `_ZN3art15GetOsThreadStatEiPcm`） | stat 线程数字段不可信；raw syscall read 直通内核安全；read 的伤痕由 #10 覆盖 |
| FDListCloaker：藏 injector fifo/ctrlfd | cloak.vala:218-235 | /proc/self/fd 枚举必须走 raw getdents64 |
| Gum.Cloak 内存范围隐藏 | agent.vala:141 add_range(cached_agent_range) | 仅影响 gum 自身 API 的枚举，不影响 procfs |
| memfd 注入 | linjector.vala:253-281（`SELinux.fsetfilecon "u:object_r:frida_memfd:s0"`） | maps 里路径显示为 `/memfd:... (deleted)` —— 注意 SELinux context `frida_memfd` 本身是一个可探测的高置信指标（若设备保留 context） |

## 综合判定阈值

score ≥ 30 → detected（权重见 frida_detect.c `fr_detect_all` 末段）。
设计理由：单通道（尤其匿名 RX、TracerPid 窗口、fs 瞬时项）都可能是误报，
要求多通道共振；高分通道（线程名 50、phdr 40）单独可定罪，因为其误报率近零。

### 勘误补充（ThreadCountCloaker 的 read hook 位置）
更正一处精度问题：ThreadCountCloaker 对 `read` 的 hook 不是挂在 libc 的
`read` 导出上，而是改写 **libart 的 GOT slot**（`art.enumerate_imports` 拿到
libart 内 `read` 的导入槽，cloak.vala:70-77 `update_slot`）。因此：
- #10 哨兵名单里的 `read`（libc 导出序言）**测不到这个 hook**——它伤在
  libart 的 .got（数据段），不在 libc .text。
- 对抗边界结论不变但更精确：ThreadListCloaker/FDListCloaker 的六件套
  （libc .text 序言伤痕）是 #10 的主证据；ThreadCountCloaker 的 read
  伤痕在 libart GOT，可用"libart GOT 项 vs libc read 导出地址比对"单列
  （GOT 劫持检测，经典手法，实现留给 maps 清洗阶段一并做）。

## 检测项 #11 详述：GOT 导入槽劫持检测（detect/detect_got_slots.c）

> 范围声明：纯静态比对逻辑，本轮不执行。实测频率标注 `待实测`。

**判据（源码可证）**：ThreadCountCloaker 改写 libart 的 GOT 导入槽——
cloak.vala:62-82 `art.enumerate_imports` 取 `read` 与 `_ZN3art15GetOsThreadStatEiPcm/Pcj`
的 slot，`update_slot` 改指自家 `on_read`/`on_get_os_thread_stat`
（cloak.vala:107-141）。GOT 落 rw- 数据页，**#10（.text 序言）与 #2b/#5
（匿名 RX）对它全盲**——「.text 干净 ≠ 没被 hook」的实证。实现遍历目标 so
的 .rela.plt/.rela.dyn（JUMP_SLOT / GLOB_DAT），`*slot` vs `dlsym` 真值比对。

| # | 检测项 | 读取的 API | 原版命中概率 | 误报风险 | 对抗难度 |
|---|---|---|---|---|---|
| 11 | GOT 导入槽劫持（libart read/GetOsThreadStat 槽） | `dl_iterate_phdr` 定位模块 + 磁盘 ELF 解析 .rela.* + `dlsym` 真值 | **高**（源码可证 cloak 必改两槽；实测 `待实测`） | 中（lazy binding/跨库实现，见下） | 高——魔改改槽必经 mprotect（内核留痕可另列），或彻底放弃读 hook 改内核侧 |

### (a) FULL RELRO 静态判据（readelf 等价口径）
- `readelf -l`：存在 **PT_GNU_RELRO** segment；
- `readelf -d`：**DT_BIND_NOW**（或 DT_FLAGS 的 DF_BIND_NOW / DT_FLAGS_1 的
  DF_1_NOW）；
- 两者齐备且 RELRO 段范围覆盖 .got(+.got.plt) = **FULL RELRO**（加载后 linker
  mprotect 只读）。只有 RELRO 无 BIND_NOW = PARTIAL（.got.plt 仍 rw，lazy 生效）。
- bionic linker 口径与 glibc 一致；Android 6+ 系统 so（含 libart）普遍 FULL RELRO。

### (b) 只读 GOT 下判据是否稳定 —— 稳定
RELRO 只限**写**（linker reloc 完成后 mprotect PROT_READ）。读 `*slot` 永远合法。
Frida 改槽必须 mprotect rw → 写 → （可还原 ro），无论还原与否，被改过的槽
读出来都是劫持地址——比对判据不受页属性影响。额外收益：改槽的 mprotect
本身是可单列的内核侧痕迹（prctl/procfs 不可直接看，但 /proc/self/maps 的
该页 vma flags 翻转窗口可采样）。

### (c) lazy binding 未解析槽的误报规避
PARTIAL RELRO + lazy 时未解析 JUMP_SLOT 的 `*slot` 指向本模块 PLT 桩
（push index → resolver），非目标函数。规避：若 `*slot` 落在**本模块自身
PT_LOAD(PF_X) 区间** → 判 `unresolved-skip` 不比对。GLOB_DAT（.rela.dyn）
加载即解析，无此问题，优先采信。Android 6+ 系统 so 基本 BIND_NOW，lazy
场景仅限老设备/自编译 so。

### 误报控制（三类）
1. **`__libc_` 别名**：libart 导入的是 `read`（非 `__libc_read`），dlsym("read")
   与 linker 解析结果同源，diff=0，无干扰。
2. **IFUNC resolver**：实现里显式跳过 R_AARCH64_IRELATIVE（IFUNC 内部重定位，
   槽值合法指向 resolver 结果，非劫持）；目标符号 read/open 非 IFUNC 导入形态。
3. **跨库实现**（`read` 被 libart 静态链接或由 libc++ 提供）：`dlsym(RTLD_DEFAULT)`
   返回**全局最新**定义，可能与 libart 实际绑定的库不同 → 槽值≠dlsym 值但非
   劫持。处理：diff 命中后回查 `*slot` 是否落在任一已加载模块的文件背书
   可执行段（dl_iterate_phdr 全模块区间表）——落文件背书区 = cross-lib 降级
   为 `cross-lib-skip`，落匿名区/拦截器页 = HIJACKED（Gum hook 的
   on_read/on_get_os_thread_stat 是 agent 内部函数，必落 agent 映射——memfd
   或匿名，无文件背书，天然可分）。

### 判定标准（`待实测`）
待授权后：原版 frida attach 后 fr_detect_got_hijack() 应报 libart 的
`read` 槽 HIJACKED（*slot 落 agent 映射），未注入时 clean 或 cross-lib-skip。
