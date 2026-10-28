# 原版 Frida 指纹面全景盘点（源码级证据）

> 基线：`D:\tools\apk-reverses\frida-mg`（frida 17.x 线）
> submodule：`subprojects/frida-gum` @ `e1f746fe` · `subprojects/frida-core` @ `61708ddb`
> 文中所有「证据」均为 **文件:行**，可直接 `sed -n` 复核。凡未在源码里命中的说法，一律标注为「检测器历史名单/待验证」，不当作事实。
>
> **本轮范围（用户已明确）**：**仅源码级静态分析**。不调用任何模拟器（MuMu 等）、不做设备侧动态验证、不构建不部署。
> 因此本文里所有「运行时会看到什么」的结论都是 **源码推导**，不是实机采样；需实机确认的项已在 `02` §9 单独列清单，不与已验证结论混排。
> 另：本分析针对 **arm64 真机语义**（redirect 形态、BTI/PAC 均按 arm64 讲），x86 模拟器上的形态不同且不在本报告范围内。

---

## 0. 一句话结论

原版 Frida 的可检测面分 5 层，**真正决定成败的不是"改名"，而是"agent 在目标进程里的映射形态"与"是否改写了 .text"**。
改名只解决"被清理"和"名单式扫描"，解决不了"目标进程自省 + 完整性校验"。

---

## 1. 指纹分层模型

检测者能读到的信息来源，按「获取成本」从低到高排列，也就构成了我们的对抗优先级：

```
① 命名层    线程名 / 库名 / 进程名 / 目录名 / D-Bus 名 / 抽象 socket 名   ← 成本最低，检测器最爱用
② 映射层    /proc/self/maps 里的路径与权限 (memfd、匿名 RX 页、SELinux label)
③ 通信层    TCP 27042/27052、unix abstract `/frida-<uuid>`、D-Bus 握手
④ 结构层    函数序言被改写 (4/8/16 字节 redirect)、thunk 页、libart/libc .text 与磁盘不一致
⑤ 内核层    TracerPid、SELinux 文件上下文、tombstone、时序、崩溃栈
```

**关键区分（很多人栽在这）**：指纹分「目标进程内可见」与「frida-server 进程内可见」两套。
检测 App 只看得到第 1 套。所以 server 侧改名（进程名、端口）**不属于反检测手段，属于反清理手段**。

| 可见性 | 出现在 | 例子 |
|---|---|---|
| **目标进程内**（App 能自省到） | App 自己的 `/proc/self/*` | `gum-js-loop` 线程、`memfd:...frida-agent-64.so`、被改写的 `.text` |
| **系统面**（外部观察者/风控 SDK 后台能查到） | `ps`、`/proc/net/*` | `frida-server` 进程、`127.0.0.1:27042` 监听、`@/frida-<uuid>` 抽象 socket |
| **内核面**（只有 root/内核能读） | SELinux、ptrace 状态 | `u:object_r:frida_memfd:s0`、短时 `TracerPid` |

---

## 2. ① 命名层

### 2.1 线程名（目标进程内，最强单点信号）

| 线程名 | 证据 | 出现位置 |
|---|---|---|
| **`gum-js-loop`** | `frida-gum/bindings/gumjs/gumscriptscheduler.c:117` → `g_thread_new ("gum-js-loop", ...)` | **目标进程**，随 JS 脚本执行环境常驻 |
| `frida-gadget` | `frida-core/lib/gadget/gadget-glue.c:115` | gadget 宿主进程 |
| `frida-gadget-tcp-<port>` | `frida-core/lib/gadget/gadget.vala:585` | gadget 进程（线程名里**直接编码端口号**） |
| `frida-gadget-unix` | `frida-core/lib/gadget/gadget.vala:596` | gadget 进程 |
| `frida-eternal-agent` | `frida-core/lib/agent/agent.vala:387 / 583 / 691` | 目标进程（eternal agent 模式） |
| `frida-agent-emulated` | `frida-core/lib/agent/agent.vala:1453` | 目标进程（emulated 后端） |
| `frida-agent-container` | `frida-core/src/agent-container.vala:108` | 目标进程（硬化目标才用容器） |
| `frida-server-main-loop` | `frida-core/server/server.vala:183` | server 进程 |
| `frida-android-helper` | `frida-core/src/linux/linux-host-session.vala:563` | server 进程 |
| `pool-frida`（历史名） | **本版本 grep 未命中** | 检测器名单里仍普遍存在 → 说明检测器靠"历史字面量名单"，改名即可绕 |

读取方式（App 自省，零成本）：

```c
// /proc/self/task/*/comm  或  pthread_getname_np
DIR *d = opendir("/proc/self/task");
```

> **结论**：`gum-js-loop` 是本仓库里唯一"目标进程内必现、且由源码字面量硬编码"的线程名。**它是第一优先级 patch 点**。

### 2.2 库名 / 符号 / 目录

| 指纹 | 证据 |
|---|---|
| agent 资源名模板 **`frida-agent-<arch>.so`** → `frida-agent-64.so` | `frida-core/src/linux/linux-host-session.vala:69` → `PathTemplate ("frida-agent-<arch>.so")` |
| 导出符号 **`frida_agent_main`** | `frida-core/lib/agent/meson.build:39`、`frida-core/src/agent-container.vala:33` |
| `agent_name = 'frida-agent' + shlib_suffix` | `frida-core/meson.build:228` |
| gadget 名族 `frida-gadget` / `libfrida-gadget-modulated.so` | `frida-core/lib/gadget/meson.build:62 / 85-87` |
| 临时目录 **`re.frida.server`** | `frida-core/server/server.vala:6 / 202` |
| gadget 标识 `re.frida.Gadget` | `frida-core/lib/gadget/gadget.vala:1729` |

### 2.3 JS 内嵌资源里的字面量（在 agent 的 rodata 里）

| 字符串 | 证据 |
|---|---|
| **`frida:rpc`** | `frida-gum/bindings/gumjs/runtime/message-dispatcher.js:24 / 69 / 71 / 73`、`runtime/worker.js:31` |

> 这类 JS 文件被编进 agent 的嵌入资源，**字符串静态可搜**。App 只需要在自身内存里 `memmem("frida:rpc")` 就能判定。这条常被忽略，但它是**免 syscall、免 hook、抗改名**的检测法，因此魔改时必须一起改。

---

## 3. ② 映射层

### 3.1 agent 的加载形态（决定 maps 里写什么）

源码证明：现代 frida 在 Android 上**优先用 memfd 注入**，而不是落盘 so：

| 事实 | 证据 |
|---|---|
| `MemoryFileDescriptor`（memfd）受支持时走 memfd | `frida-core/src/linux/linux-host-session.vala:163-166` → `path = "/proc/self/fd/%d"` |
| 注入通过 `inject_library_fd`（fd 注入，无文件路径） | `frida-core/src/linux/linjector.vala:94` |
| memfd 创建用 agent 资源名 | `frida-core/src/linux/linjector.vala:253-261` → `MemoryFileDescriptor.from_bytes (name, blob)` |
| **SELinux 上下文被显式设置** | `frida-core/src/linux/linjector.vala:281` → `u:object_r:frida_memfd:s0`；落盘路径则 `u:object_r:frida_file:s0`（`linjector.vala:268/276`） |

因此映射在 `/proc/self/maps` 里通常呈现为：

```
7f1a2b0000-7f1a2b4000 r-xp 00000000 00:01 12345   /memfd:frida-agent-64.so (deleted)
```

或（内核按 fd 路径呈现时）`/proc/self/fd/N`。**无论如何都带 `frida-agent` 字样** —— 这是目标进程自省的头号命中点。

### 3.2 匿名可执行映射（trampoline 页）

| 事实 | 证据 |
|---|---|
| 4/8/16 字节三种序言改写在同一函数内实现 | `frida-gum/gum/backend-arm64/guminterceptor-arm64.c:1205-1246` |
| 16 字节形态 = `ldr xN,#8; br xN; <u64 target>` | 同上 `case GUM_INTERCEPTOR_FULL_REDIRECT_SIZE`（`put_ldr_reg_address` + `put_jmp_reg`），`GUM_INTERCEPTOR_FULL_REDIRECT_SIZE 16` @ `:30` |
| 8 字节形态 = `adrp xN,...; br xN` | 同上 `case 8` |
| 4 字节形态 = 近跳 `b <imm26>` | 同上 `case 4`；近距 thunk 只在 `HAVE_LINUX` + 可容纳时启用（`:713-733`） |
| thunk 页是**匿名 mmap 出来的 RX/RW 页**，且被登记进 cloak | `guminterceptor-arm64.c:1394-1401`（`gum_memory_allocate` + `gum_cloak_add_range`） |

对应机器码（arm64 小端）：

```
16 字节: 50 00 00 58 | 00 02 1F D6 | <8B 目标地址>      ; ldr x16,#8 ; br x16
 8 字节: ?? ?? ?? 90 | ?? ?? 1F D6                       ; adrp x16,... ; br x16
 4 字节: ?? ?? ?? 14                                    ; b <imm26>
```

> **这是静态可校验的**：拿 `/proc/<pid>/maps` 里的 `libart.so`/`libc.so` 基址 + 偏移，与磁盘文件同偏移字节比对，只要 hook 过，序言必然不一致。检测器不需要任何"frida"字样就能判定"有 inline hook"。

#### 3.2.1 但 `.text` 干净 ≠ 没被 hook：GOT 劫持（很多人漏掉）

`frida-core/lib/payload/cloak.vala:62-82` 的 `ThreadCountCloaker` **根本不改代码**，它改的是 **`libart.so` 的导入槽（GOT）**：

```
art = Gum.Process.find_module_by_name ("libart.so");
art.enumerate_imports (imp => {
  if (imp.name == "_ZN3art15GetOsThreadStatEiPcm") get_os_thread_stat_slot = imp.slot;
  else if (imp.name == "read")                    read_slot = imp.slot;
});
update_slot ((void **) read_slot, (void *) on_read);      // ← 改 GOT 项指向自家函数
```

由此得出三个必须知道的事实：

| 事实 | 后果 |
|---|---|
| GOT/`.data.rel.ro` 是 **rw-** 数据页，不是可执行页 | §3.3 的"匿名 RX 页"判据、§3.2 的 `.text` 比对 **都抓不到它** |
| 改写目标是 `libart` 的导入槽 | 检测方式：枚举目标模块 `enumerate_imports` 的同名槽，看它是否等于 `dlsym(libc, "read")`；不等即被劫持 |
| Frida 自己就靠这招藏线程数 | 说明"无代码改写"的 hook 是真实可行的主流手法 → P3（去 Interceptor）反而会**新增**这类指纹 |
| **改槽前必须先解除只读**（若目标 so 是 FULL RELRO） | RELRO 判据：`PT_GNU_RELRO` + `DT_BIND_NOW`/`DF_BIND_NOW`/`DF_1_NOW` 且 RELRO 段覆盖 `.got`（Android 6+ 的 `libart` 普遍 FULL RELRO）。→ Frida 必须 `mprotect(rw)` → 写槽 →（可还原），于是 **`/proc/self/maps` 里该数据页的 vma flags 会出现 `r--p → rw-p → r--p` 的翻转窗口**，这是第三条可采样的结构面证据 |
| **槽落点背书法（通用判别，不依赖符号名）** | `*slot` 落在「有文件背书的可执行段」= 合法跨库绑定或 PLT 桩（跳过）；落在**匿名段或 memfd** = 必是劫持（Gum 的 `on_read` 是 agent 内部函数，必然落在 agent 自己的映射上） |

> 结论：完整的结构面检测需要 **三条**：`.text vs 磁盘`、`匿名 RX 页`、**`GOT 项 vs 导出符号`**。只做前两条会漏掉目前 Frida 实际使用的一种隐藏手法。

### 3.3 匿名可执行映射的**误报控制**（检测侧必须做，否则一天到晚误杀 JIT）

三条可用判据（源码可证）：

| 判据 | 证据 |
|---|---|
| **batch 尺寸指纹**：Gum 代码分配器每批固定 **7 页** | `frida-gum/gum/gumcodeallocator.c:144` → `allocator->pages_per_batch = 7;` |
| **哨兵函数归属校验**：`dlsym` 取 `malloc`/`strlen`/`open` 的地址，若落在"无 pathname 的 RX 段"内 → 该段劫持了 libc 导出；JIT 页不会持有 libc 符号 | §3.2 的 redirect 形态 + 导出符号表 |
| **跳过命名匿名段** `[anon:...]`（ART JIT、Vulkan、`jit-cache` 常以此命名），只对**无名** RX 段加权 | `awk '$6==""'` |

### 3.4 已有的 cloak 能力 —— **两层**，边界各不相同（重要，容易误判）

Frida 的"自隐藏"实际是两套完全不同的机制，混为一谈就会算错可检测面。

**第一层：gum 内部枚举隐藏**（只骗 Frida 自己）

`frida-gum/gum/gumcloak.h` 提供 thread / range / fd 三类隐藏：

```c
GUM_API void gum_cloak_add_thread (GumThreadId id);
GUM_API void gum_cloak_add_range (const GumMemoryRange * range);
GUM_API void gum_cloak_add_file_descriptor (gint fd);
```

作用范围仅限 `Process.enumerateRanges/Threads/Fds`。**对 `/proc` 零作用。**

**第二层：payload 的目录列表过滤**（这一层会真的骗到 App —— 但有前提）

`frida-core/lib/payload/cloak.vala` 里有 `ThreadListCloaker:199`、`FDListCloaker:218`、`ThreadCountCloaker:46/194`，
其底层 `DirListCloaker:237-284` 用 Interceptor 挂了 libc 的 **6 个符号**：

```
opendir / closedir / readdir / readdir64 / readdir_r / readdir64_r     (cloak.vala:257-284)
```

于是 App 若用 `opendir("/proc/self/task")` + `readdir()` 枚举线程，**`gum-js-loop` 等条目会被过滤掉**。

> **但有三个致命前提，必须记住：**
> 1. **只挡 libc 路径**。App 直接发 `getdents64` syscall（或 `syscall(__NR_getdents64)`）→ 过滤完全失效，条目照样出现。检测工装必须走 raw syscall，否则自己骗自己。
> 2. **它自己就是指纹**。这 6 个 `Interceptor` hook 会在 **libc 的 .text 上开 6 个 inline hook**（`opendir`/`readdir` 序言被改写成 4/8/16 字节 redirect，见 §3.2）。**Frida 为了藏自己，反而在 libc 上多留了 6 处结构层证据** —— 一把"内存 libc .text vs 磁盘 libc"比对就能抓出，且完全不需要出现 `frida` 字样。
> 3. **不挡内核视角**。debuggerd 崩溃 dump 由独立进程读 `/proc/<pid>`，cloaker 拦不到（见 §5）。

**结论**：把 cloak 当成"能过检测"是错的，当成"多开 6 个 libc hook"才对。魔改时的正解是**直接改掉字面量/名字**（§2.1），而不是依赖 cloak。

---

## 4. ③ 通信层

| 指纹 | 证据 | 备注 |
|---|---|---|
| 控制端口 **27042** | `frida-core/lib/base/socket.vala:4` → `DEFAULT_CONTROL_PORT = 27042` | `/proc/net/tcp` 中呈现为 `0100007F:69A2`（0x69A2 = 27042） |
| 集群端口 **27052** | `frida-core/lib/base/socket.vala:5` → `DEFAULT_CLUSTER_PORT = 27052` | 0x69AC |
| 默认绑定 **127.0.0.1** | `frida-core/lib/base/socket.vala:18` → `parse_frida_address(..., "127.0.0.1", default_port)` | 只本机可见，但仍可被 `connect()` 探活 |
| **抽象 unix socket `/frida-<uuid>`** | `frida-core/src/linux/frida-helper-process.vala:341-345` | **最易被忽略的硬指纹**：`/proc/net/unix` 里出现 `@/frida-xxxx`，与 server 是否改名无关 |
| **第二族抽象 socket `/frida-zymbiote-<uuid>`** | `frida-core/src/linux/linux-host-session.vala:1576-1580`（`"/frida-zymbiote-" + Uuid.string_random()` → `socket.bind (address, true)` + `socket.listen ()`，ABSTRACT 类型） | **两族名字不同、前缀不同**：只改 helper 那处会漏。zymbiote 是「注入到运行中进程」链路的监听 socket，就在 server 进程里 |
| D-Bus 接口名族 `re.frida.*17` | `frida-core/lib/base/session.vala:4/51/66/110/131/759/787/794/804/810/819/826/1222` | 握手/认证阶段的协议特征，可被抓包识别 |
| helper 进程 nice-name **`re.frida.helper`** | `frida-core/src/android-helper/client.vala:42` → `--nice-name=re.frida.helper re.frida.Helper %s; rm -f %s; echo BYE.` | `ps` 可见；注意同一行里还有 `rm -f` 的自清理逻辑 |
| **D-Bus server GUID = `github.com/frida`**（SASL `OK <guid>` 明文可见） | `frida-core/lib/base/session.vala:2781` → `ServerGuid.HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461"`，hex 解码即 `github.com/frida` | 单常量，8 处引用自动跟随 |
| **D-Bus object path 家族 `/re/frida/*`** | `frida-core/lib/base/session.vala:2784-2795`（`HostSession` / `AgentSession` / `AgentController` / `AgentMessageSink` / `GadgetSession` / `Channel` / `Service` / `TransportBroker` / `PortalSession` / `BusSession` / `AuthenticationService` 等 12 条） | 与接口名族分开命名，容易漏改 |
| **`User-Agent: Frida/<version>` + 自定义 `Host` 头** | `frida-core/lib/base/socket.vala:242-256`（WS 升级请求构造） | 设备侧被动抓不到，但 loopback 抓包或 hook 了 `send()` 的检测模块可见；host 侧调用方传 `lolcathost` |

**运行时可控项（无需重编译）** —— 见 `frida-core/server/server.vala:33-57` 的 `option_entries`：

```
--listen/-l ADDRESS     --directory/-d DIRECTORY     --token TOKEN
--certificate FILE      --origin ORIGIN              --asset-root ROOT
--daemonize/-D          --policy-softener system|internal
```

> 也就是说 **端口与工作目录只是启动参数**，`frida-server -l 127.0.0.1:53311 -d /data/local/tmp/.x` 即可改写两个最高频指纹，零编译成本。
> 而 **D-Bus 名族、抽象 socket 名、线程名** 没有运行时开关，**必须改源码**。

---

## 5. ④⑤ 结构层 / 内核层

| 指纹 | 检测方式 | 原版是否可消除 |
|---|---|---|
| 函数序言被改写 | maps 基址 + 磁盘文件字节比对（不需要关键字） | 只能换 hook 实现（改走 ArtMethod / GOT / 数据面） |
| 匿名 RX thunk 页 | maps 里 `r-xp` 且 pathname 为空 | 可弱化（就近 thunk 合并进已有映射），彻底消除需内核。**误报重灾区**：ART JIT / Vulkan 也是匿名可执行。可靠区分条件见 §3.3 |
| `libart.so` 内存文本段 ≠ 磁盘 | 同上比对 | 仅当不再 inline hook ART 时成立 |
| **`libart` 的 GOT 导入槽被改指匿名内存** | `enumerate_imports` 取槽位，与 `dlsym(libc, 同名)` 比对（见 §3.2.1） | `ThreadCountCloaker` 干的正是这个（`lib/payload/cloak.vala:62-82`）。`.text` 全干净也会被这条抓住 |
| SELinux `frida_memfd` / `frida_file` | root 侧 `ls -Z` / `getfilecon` | 改源码字面量即可改 label（`linjector.vala:268/275/281`，第 4 处在 `lib/pipe/pipe.vala:172`） |
| **server 存活期把自定义 SELinux type 写进内核 policy** | root 侧 `grep -a frida_file /sys/fs/selinux/policy` —— **一击命中，重启前持续存在，比扫端口稳得多** | 两条路：改 type 名（功能零代价）；删掉注入改已有 type（丢 spawn/zygote）。**gadget 路线完全不走这条路径** |
| **`frida_selinux_patch_policy()` 只有 3 个调用点，且不含 gadget** | `server/server-glue.c:64`、`inject/inject-glue.c:14`、`tests/runner-glue.c:47`；`lib/gadget/gadget-glue.c` 不含 `frida-selinux.h`；`lib/gadget/meson.build:72` 的 deps 无 `frida_selinux_dep` | **gadget 内嵌路线天然不注册自定义 type、不写 `/sys/fs/selinux/load`** → 这一整类指纹对 gadget 不存在 |
| `TracerPid != 0` | `/proc/self/status` | 只在 ptrace attach 期间出现；注入后即 `DETACH`（`src/linux/frida-helper-backend.vala:677`、`:1990`）→ 稳态 `TracerPid=0`，**不是稳定信号**，只有"注入瞬间"能被抓。原版 `Seccomp` 字段为 0，同样不可用 |
| **tombstone / 崩溃栈**里出现 `gum-js-loop` 帧 | 崩溃后 debuggerd 读 `/data/tombstones` | 改线程名后**名字**消失，但**帧本身仍在**。且 debuggerd 是**独立进程**读 `/proc/<pid>`，`DirListCloaker` 完全拦不到 → **这条是用户态最难对抗的检测面之一** |
| BTI/PAC 兼容 | — | **已内建，不要删**：`frida-gum/gum/backend-arm64/asmdefs.h:19-20`（`BTI_C/BTI_J`）、`:45-52`（`GNU_PROPERTY FEATURE_1_BTI|PAC`）、`gum/arch-arm64/gumarm64writer.c:1852` 注释（"branches may reach it on a BTI-guarded page…"）。删掉 landing pad → Android 14+ BTI 设备直接崩 |

---

## 6. 五条反常识结论（本次盘点的真正价值）

1. **改名不等于隐身。** agent 活在目标进程里，`maps` 里必然有一条带 `frida` 的可执行映射。server 改名只挡"清理清扫"，挡不住"自省检测"。
2. **`gum_cloak` 有两层，别混淆**：gum 层只骗 Frida 自己的枚举 API（`gumcloak.h`，对 `/proc` 零作用）；payload 层（`lib/payload/cloak.vala:237-284`）确实会 hook libc 的 6 个目录函数去滤掉 `/proc/self/task`、`/proc/self/fd` 条目，**但只挡 libc 路径**（raw `getdents64` 直通无效），**并且这 6 个 hook 本身就是 libc .text 上的结构层指纹**。
   → 依赖 cloak 藏的代价，比直接改名更高。注意 cloak 的成本不只有 6 个 libc hook：`ThreadCountCloaker` 还改了 `libart.so` 的 **GOT 导入槽**（`lib/payload/cloak.vala:62-82`），而 GOT 在 **rw- 数据页**上 —— `.text` 比对与匿名 RX 页两条判据都抓不到它（§3.2.1）。
3. **端口/目录零成本可改（启动参数），D-Bus/抽象 socket/线程名必须重编译。** 这决定了工作量分配。
4. **重编译 frida-core 有硬门槛**：`frida-core/meson.build:11-19` 要求 Vala 编译器版本以 `-frida` 结尾，即必须先跑 `https://github.com/frida/vala` 自编译一套 Vala。CI 还需要 NDK **r29**（`.github/workflows/ci.yml:16`）与 Go 工具链（`FRIDA_COMPILER_MOD`，`:15`）。
   → **这条门槛直接决定了方案选型**：patch 官方 core 的成本远高于"自建 gum agent"。详见 `02-魔改方案与验收.md`。
5. **比起端口，SELinux policy 才是最难洗的指纹。** `server/server-glue.c:63-65` 在 Android 上启动即调 `frida_selinux_patch_policy()`，`lib/selinux/patch.c:85/92` 会把 `frida_file` / `frida_memfd` 两个自定义 type **注入内核 policy**并写回 `/sys/fs/selinux/load`。
   → 即便改了二进制名、关了端口，只要 server 跑过一次，root 侧 `grep -a frida_file /sys/fs/selinux/policy` 就命中了。
   **两种解法代价不同**：改名（`patch.c` 里 **5 处** type 字面量：`"frida_file"` @ `:42/:43/:85`、`"frida_memfd"` @ `:44/:92`）功能零代价，但仍是“陌生名”；彻底删除注入能根除指纹类，却会连带丢掉 `patch.c:41-53` 的 **13 条 allow 规则**（含 `execmem`、`shell_data_file`、`zygote_exec`）→ **spawn / `frida -f` / zygote 注入失效**。
   **真正的结构性解是 gadget**：`frida_selinux_patch_policy()` 的 3 个调用点里**没有 gadget**（`server-glue.c:64` / `inject-glue.c:14` / `runner-glue.c:47`），gadget 的载荷是 APK 自带 native 库，不需要新 type、不需要 relabel、不写内核策略。

---

## 7. 附录：外部视角的"一键取证"命令（不受目标进程 hook 影响）

> **说明**：以下是给后续**授权实测**准备的取证口径，本轮不执行（无模拟器、无设备操作）。

这些命令从 **shell/root 外部**执行，因此**无法被目标进程内的 hook 欺骗**（除非内核级）。既是我们的验收手段，也是风控方的真实杀招。

```bash
PID=<target pid>

# ① 线程名
adb shell "ls /proc/$PID/task | while read t; do cat /proc/$PID/task/\$t/comm; done" | sort -u

# ② 映射（frida / gadget / memfd / 匿名 RX）
adb shell "cat /proc/$PID/maps" | grep -Ei 'frida|gadget|linjector|memfd|gum'

# ③ 匿名可执行页（无 pathname 的 r-xp）
adb shell "awk '\$2 ~ /x/ && \$6 == \"\"' /proc/$PID/maps"

# ④ 监听端口（27042=0x69A2 / 27052=0x69AC）
adb shell "cat /proc/net/tcp /proc/net/tcp6" | grep -Ei '69A2|69AC'

# ⑤ 抽象 socket
adb shell "grep -a frida /proc/net/unix"

# ⑥ 进程名 / nice-name
adb shell "ps -A -o PID,NAME,ARGS" | grep -Ei 'frida|re\.frida'

# ⑦ SELinux 上下文（需 root）
adb shell "su -c 'ls -lZ /proc/$PID/fd'" | grep -i frida

# ⑧ .text 完整性（hook 判定的"无关键字"检测法）
#    取 maps 中 libart.so 的基址与文件偏移，与磁盘文件同偏移比对字节
adb shell "cat /proc/$PID/maps" | grep libart.so
```

> 验收纪律：**不要用魔改后的 Frida 自己去跑检测脚本来自证"看不见"**——那只能证明"检测函数被 hook 后不报警"。必须以上述**外部视角**为主证据，进程内自省为辅。这一条写进了 `02` 的验收矩阵。
