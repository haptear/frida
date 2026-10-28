# SELinux 指纹处置：A / B 两套 patch

> **范围声明**：本文**只含源码级静态分析与 patch 文本**。不含设备侧动态验证、不含构建/部署、不调用模拟器。
> 凡需设备或编译才能确认的结论，一律单列在 **§6 待实测清单**，不与源码可证结论混排。
> 基线：`subprojects/frida-core` @ `61708ddb0c8f55eaf363385d8647c9a385660fa5`。所有证据为 `文件:行`，可 `sed -n` 复核。

---

## 0. 结论先行：三层场景选型（与主报告 `02` §0.1 一致）

> 本节为**最终裁决**（叮叮）。下面的 §1–§8 都是为这张表提供证据。

| 场景 | 选什么 | 理由（证据位置） |
|---|---|---|
| **允许内嵌 APK** | **gadget**（A / B **均不需要**） | gadget 不调用 `frida_selinux_patch_policy()`，天然不注册自定义 type、不写内核策略、不给载荷打自定义标签 → 天然免疫整类指纹。四条独立证据见风险-2 交付件 `02-GADGET-ROUTE.md` §0 / §8 |
| **server + 需要 spawn / zygote**（`frida -f`、spawn-gating、zygote 注入、system_server 注入） | **B（改名）** —— **默认方案** | A 会删掉 `patch.c:41-53` 全部 13 条 allow 规则，其中 `:41 execmem` / `:45 shell_data_file:dir search` / `:46 zygote_exec:file execute` 是这些能力的硬前提；B 保留全部规则，功能零代价 |
| **server + 仅 attach，且 §6 实测通过** | **A**（根除指纹类） | 唯一能同时消除「内核审计事件 + 可名单化 type + 载荷自定义标签」三项的方案 |

**默认位 = B；A = 待实测条件选项；gadget = 结构性最优。**

> ❗ **B 的能力上限（必须一起读）**：B 只能过**名单式检测**（`grep -a frida /sys/fs/selinux/policy`、`ls -Z` 找 frida 串）。
> 遇到**白名单式检测**（设备 policy 与 AOSP 基线 diff，出现非 stock type 即异常）→ **B 无效**，
> 此时只能上 **A**（需实测通过）或 **gadget**。详见 §4.4。

A 的启用前置（两者全过才能上，见 §6）：
- ① AOSP 已给目标域 `self:process execmem`
- ② server 所在域对目标 type 有 `relabelto`

任一不通过 → 直接落 B。

---

## 1. 文件与应用方式

| 文件 | 内容 | 改动文件数 |
|---|---|---|
| `selinux-A-remove-policy-injection.patch` | 删 `frida_selinux_patch_policy()` 调用 + 4 处 `setfilecon` 改用**设备上已有**的 type + 摘掉 libsepol 编译单元 | 7 |
| `selinux-B-rename-types.patch` | **仅** `lib/selinux/patch.c` 的 5 处类型名改名 | 1 |

```bash
cd subprojects/frida-core
git apply --check _stealth/patches/selinux-A-remove-policy-injection.patch   # 已核对：7/7 通过
git apply         _stealth/patches/selinux-A-remove-policy-injection.patch
# 或者
git apply         _stealth/patches/selinux-B-rename-types.patch
```

⚠️ **A 与 B 互斥**，不要同时打。

`git apply --check` 结果（本地已跑，纯文本校验、不编译不写文件）：
```
selinux-A-remove-policy-injection.patch : server-glue.c inject-glue.c patch.c lib/selinux/meson.build meson.build linjector.vala pipe.vala  → 7/7 OK
selinux-B-rename-types.patch            : patch.c → 1/1 OK
```

---

## 2. 源码可证：上游到底改了什么

### 2.1 唯一入口：3 个调用点

```
server/server-glue.c:64         frida_selinux_patch_policy ();   (在 #ifdef HAVE_ANDROID 内)
inject/inject-glue.c:14         frida_selinux_patch_policy ();   (在 #ifdef HAVE_ANDROID 内)
tests/runner-glue.c:47          frida_selinux_patch_policy ();
```

`lib/gadget/gadget-glue.c` **不在其中**（详见风险-2 交付件 `02-GADGET-ROUTE.md` §8「gadget 是否注入 SELinux 策略」）。

### 2.2 它做的事

`lib/selinux/patch.c:59-170`：
1. `:62` 读 `/sys/fs/selinux/policy`
2. `:80-97` 用 `frida_ensure_type()` 注入两个新 type（`:85` `frida_file`、`:92` `frida_memfd`，属性 `file_type, mlstrustedobject`）
3. `:99-145` 逐条应用 `frida_selinux_rules[]`（`:39-54`）
4. `:147` 把整份策略写回 `/sys/fs/selinux/load`
5. `:151-160` 失败时**临时 `security_setenforce(0)`** 再恢复（模拟器兜底）

### 2.3 被注入的 13 条 allow 规则（`patch.c:41-53`，逐行）

| 行 | 规则 | `?` 前缀 | 语义 |
|---|---|---|---|
| 41 | `domain → domain:process execmem` | 无（必需） | 目标域自映射可执行内存 |
| 42 | `domain → frida_file:dir search` | 无（必需） | 遍历载荷目录 |
| 43 | `domain → frida_file:file {open read getattr execute ?map}` | map 可选 | 加载载荷 |
| 44 | `domain → frida_memfd:file {open read write getattr execute ?map}` | map 可选 | memfd 形态载荷 |
| 45 | `domain → shell_data_file:dir search` | 无（必需） | 遍历 `/data/local/tmp` |
| 46 | `domain → zygote_exec:file execute` | 无（必需） | spawn-gating / zygote 注入 |
| 47 | `domain → self:process sigchld` | 无 | 子进程管理 |
| 48 | `domain → self:fd use` | 无 | fd 传递（transport broker） |
| 49 | `domain → self:unix_stream_socket {connectto read write getattr getopt}` | 无 | unix socket 通道 |
| 50 | `domain → self:tcp_socket {read write getattr getopt}` | 无 | TCP 通道 |
| 51 | `zygote → zygote:capability sys_ptrace` | 无 | zygote 内 ptrace |
| 52 | `?app_zygote → zygote_exec:file read` | 有（可选） | — |
| 53 | `system_server → ?apex_art_data_file:file execute` | 有（可选） | — |

`?` 的语义见 `patch.c:137-141`：`if (perm[0] == '?') is_important = FALSE;` —— 带 `?` 的缺失只记日志，不带的会 `g_printerr` 报错。

**这就是"上游认为必需"的源码依据**，不是我的推测。

### 2.4 4 处载荷标签点（全部可证）

| 文件:行 | 场景 | 原标签 |
|---|---|---|
| `src/linux/linjector.vala:268` | 载荷**目录** | `u:object_r:frida_file:s0` |
| `src/linux/linjector.vala:275` | 载荷**文件**（.so / 其他） | `u:object_r:frida_file:s0` |
| `src/linux/linjector.vala:281` | 载荷 **memfd** | `u:object_r:frida_memfd:s0` |
| `lib/pipe/pipe.vala:172` | helper **pipe socket 文件** | `u:object_r:frida_file:s0` |

第 4 处在 `lib/pipe/`，由 `src/meson.build:685` `internal_libs = [base, netif, pipe] + ...` 无条件下编进 frida-core，Android 产物里也有。
`lib/selinux/patch.c` 里 `setfilecon` 的返回值**未被检查**（Vala binding 返回 int，调用处忽略），所以 relabel 失败是**静默**的 —— 只会在 `avc` 日志里留痕，不会抛异常。

---

## 3. 方案 A：删策略注入 + 复用已有 type

### 3.1 逐 hunk

| Hunk | 文件:行 | 动作 |
|---|---|---|
| A1 | `server/server-glue.c:7-9,63-65` | 删 `#include "frida-selinux.h"` 与调用，改为说明注释 |
| A2 | `inject/inject-glue.c:4-6,13-15` | 同上（保持全仓一致，避免 `frida-inject` 把 `patch.c` 拉回链接） |
| A3 | `lib/selinux/patch.c` 全文 | 替换为 29 行 no-op stub（保留符号，保留头文件导出） |
| A4 | `lib/selinux/meson.build:6-9` | `patch.c` 依赖去掉 `libselinux_dep, libsepol_dep` |
| A5 | `meson.build:779-781` | `backend_deps_private` 去掉 `libsepol_dep`，`backend_reqs_private` 去掉 `'libsepol'` |
| A6 | `src/linux/linjector.vala:268,275` | `frida_file` → `app_data_file` |
| A7 | `src/linux/linjector.vala:281` | `frida_memfd` → `app_data_file` |
| A8 | `lib/pipe/pipe.vala:172` | `frida_file` → `app_data_file` |

### 3.2 编译单元处理结论（回答"`lib/selinux/meson.build` 是否要一并处理"）

**要，但不是为了能编过，是为了"编译产物里彻底没有这个模块"。**

- 只删 `server-glue.c` 的调用，`lib/selinux/patch.c` 仍会被 mesa 编译成 `libfrida-selinux.a`；因为没有任何符号被引用，static archive 的成员**不会被拉进链接**（标准静态库语义），二进制里不会有 `frida_file` 字符串 —— **功能上已经够**。
- 但 `libselinux_dep`/`libsepol_dep` 仍参与构建（`default_library=static` + `regex=disabled`，见 `meson.build:776-779`），libsepol 会被完整编译一遍 —— 纯浪费，且 `.pc` 里仍声明 `libsepol` 依赖。
- 所以 A4 + A5 是**手尾清理**，不是必需。如果你只想最小改动，可以只打 A1/A2/A3/A6/A7/A8，跳过 A4/A5。
- **不能**删掉整个 `subdir('selinux')`（`lib/meson.build:1-3`）：`frida_selinux_vala_args = ['--pkg=libselinux']`（`lib/selinux/meson.build:16`）被 `src/meson.build:347` 引用（`backend_vala_args_private += [... frida_selinux_vala_args ...]`，块起于 `:342`），删了会导致 Vala 侧 `SELinux.setfilecon()` 找不到 `libselinux` 包而编译失败。这就是 A 保留 stub 文件、只摘 `libsepol` 的原因。

  **已核对 patch A 的 hunk 不会摘掉这两处**（叮叮 seq-26 第 3 点）：
  - A 补丁**根本不动** `src/meson.build`（7 个受影响文件里没有它）；
  - `lib/selinux/meson.build` 的 hunk 是 `@@ -3,9 +3,12 @@`，只覆盖第 **3-11** 行，第 **16** 行 `frida_selinux_vala_args` 在 hunk 范围**之外**，原样保留。
  - 复核命令：`grep -rn 'frida_selinux_vala_args' --include=*.build subprojects/frida-core` → 应得 `lib/selinux/meson.build:16` + `src/meson.build:347` 两行。

### 3.3 功能代价表（源码可证的部分）

A 让 `frida_selinux_patch_policy()` 变成 no-op ⇒ §2.3 的 **13 条规则全部不再注入**。按"是否可能影响功能"分类：

| 能力 | 依赖的规则 | A 之后的状态 |
|---|---|---|
| attach 已运行 app（写代码 + `mprotect` 可执行） | 41 `domain→domain:process execmem` | **押在 AOSP 已有规则上**（见 §6-①） |
| 载荷目录/文件加载 | 42, 43, 45 | **押在** AOSP 是否已给目标域 `shell_data_file:dir search` + 所复用 type 的 `file execute` |
| memfd 形态载荷 | 44 | 同 43，改用 `app_data_file` 标签 |
| spawn gating / `frida -f` | 46 `domain→zygote_exec:file execute` | **高风险**：`zygote_exec` 只应对 zygote 域可执行 |
| zygote 内 ptrace | 51 | 高风险 |
| system_server 注入 | 53（可选） | 中风险 |
| fd 传递 / unix / tcp 通道 | 47-50 | 低风险（`self:` 类规则 AOSP 普遍已有） |

**结论（这是给选型裁决的核心输入）**：
A 可以把"设备侧 SELinux 指纹"降到接近零，但把**注入可行性**从"我们自己保证"降级为"押注 AOSP 已给"。
**A 适用于 attach-only 场景**；需要 `frida -f` / spawn-gating / zygote / system_server 的场景，A 大概率直接失败，**应选 B**。

### 3.4 复用哪个已有 type

必需的性质是：**目标 app 的 domain 对该 type 有 `file { open read getattr execute }`**（`map` 可选）。
三个候选：

| 候选 | 理由 | 风险 |
|---|---|---|
| `app_data_file`（**补丁默认**） | app 私有数据目录的标准 type；app 自己的 native 载荷需要可执行 | 需确认目标域对该 type 有 `execute`，且 server 所在域有 `relabelto`（§6-②③） |
| `system_file` | `/system` 下文件的 type，很多域有 `read/getattr` | 对 `untrusted_app` 是否有 `execute` 更不确定 |
| **不 relabel**（把 A6/A7/A8 三处 `#if ANDROID` 块整段删掉） | 零 SELinux 接触，文件保留 `/data/local/tmp` 默认标签 `shell_data_file` | 完全押在 `domain → shell_data_file:file execute` 上；但**这是"零改动"最保守的形态**，失败与成功的判据都更清晰 |

补丁默认走 `app_data_file`；若要换，只需把 A6/A7/A8 三个 hunk 里的 `app_data_file` 换成目标串（**一处 3 行**，不要分散改）。

---

## 4. 方案 B：类型改名（回退方案）

### 4.1 实际是 **5 处**，不是 6 处

```bash
$ cd subprojects/frida-core && grep -n 'frida_file\|frida_memfd' lib/selinux/patch.c
42:  { { "domain", NULL }, "frida_file", "dir", { "search", NULL } },
43:  { { "domain", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", "?map", NULL } },
44:  { { "domain", NULL }, "frida_memfd", "file", { "open", "read", "write", "getattr", "execute", "?map", NULL } },
85:  if (frida_ensure_type (&db, "frida_file", 2, "file_type", "mlstrustedobject", &error) == NULL)
92:  if (frida_ensure_type (&db, "frida_memfd", 2, "file_type", "mlstrustedobject", &error) == NULL)
```

`frida_file` × 3（42/43/85）+ `frida_memfd` × 2（44/92）= **5 处**。
（第 6 个"处"应是把 allow 规则行 42/43 当成独立条目数了；42、43 就是 allow 规则本身，已含在内。`grep -c '"frida_file"'` = 3，`grep -c '"frida_memfd"'` = 2。）

### 4.2 B 的完整改动面 = **9 处**（不是 4 处，也不是 5 处）

`selinux-B-rename-types.patch` 只负责 `patch.c` 那 5 处（按裁决不含注入器侧）。**剩下 4 处 label 必须由 @风险3 同步改，且两批名字完全一致**。

| 批次 | 文件:行 | 原值 | 新值 | 谁改 |
|---|---|---|---|---|
| **策略侧 ①** | `lib/selinux/patch.c:42` | `"frida_file"` | `"sysd_file"` | **本 patch** |
| **策略侧 ②** | `lib/selinux/patch.c:43` | `"frida_file"` | `"sysd_file"` | **本 patch** |
| **策略侧 ③** | `lib/selinux/patch.c:44` | `"frida_memfd"` | `"sysd_memfd"` | **本 patch** |
| **策略侧 ④** | `lib/selinux/patch.c:85` | `"frida_file"` | `"sysd_file"` | **本 patch** |
| **策略侧 ⑤** | `lib/selinux/patch.c:92` | `"frida_memfd"` | `"sysd_memfd"` | **本 patch** |
| **标签侧 ⑥** | `src/linux/linjector.vala:268` | `u:object_r:frida_file:s0` | `u:object_r:sysd_file:s0` | **风险3** |
| **标签侧 ⑦** | `src/linux/linjector.vala:275` | `u:object_r:frida_file:s0` | `u:object_r:sysd_file:s0` | **风险3** |
| **标签侧 ⑧** | `src/linux/linjector.vala:281` | `u:object_r:frida_memfd:s0` | `u:object_r:sysd_memfd:s0` | **风险3** |
| **标签侧 ⑨** | `lib/pipe/pipe.vala:172` | `u:object_r:frida_file:s0` | `u:object_r:sysd_file:s0` | **风险3** |

**两批必须同名。** 只改 ①–⑤（策略侧）不改 ⑥–⑨（标签侧）→ `setfilecon("u:object_r:frida_file:s0")` 因 type 不存在而失败；
**只改 ⑥–⑨ 不改 ①–⑤（就是我上一轮口误那种写法）→ label 指向一个从未被注入的 type** → 同样 `setfilecon` 返 **-1**，
而 `patch.c` 侧本来就不检查返回值 → **静默失败、注入全挂、无任何报错**。
这就是 A 前言里点出的同一个失败模式（`patch.c` 侧不查返回值），换个位置露了一次。

**验收口径（纯静态可查）**：
```bash
cd subprojects/frida-core
grep -rn 'frida_file\|frida_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala
echo "exit=$?  # 期望 1（无匹配）"
grep -rn 'sysd_file\|sysd_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala | wc -l
echo "期望 9"
```

若要换名字，**两侧一起 sed**（共 9 处），只改一侧等于没改。

### 4.3 功能代价

**零**。B 保留全部 13 条规则与全部 4 处标签点，只换字符串。
代价：只是"换成另一个陌生名"，类型仍是自定义的、仍要写一次 `/sys/fs/selinux/load`（`patch.c:147`，这是内核审计事件）。

### 4.4 ⚠️ B 的检测上限：能过名单式，**过不了白名单式**

> 这节必须读，否则 `sysd_*` 会被误当万能解。

| 检测模型 | 判据 | B（改名） | A（删注入） | gadget |
|---|---|---|---|---|
| **名单式** | `grep -a frida /sys/fs/selinux/policy`；`ls -Z` 找 `frida_file`/`frida_memfd`；`grep -a frida` 扫二进制 | ✅ **可绕**（名字不再是 frida） | ✅ 可绕 | ✅ 天然无 |
| **白名单式** | 把设备 policy 与 **AOSP 基线** 做 diff；**出现基线里没有的 type 名即异常**，不看名字长什么样 | ❌ **无效** —— `sysd_file` / `sysd_memfd` 仍是两个非 stock type | ✅ **可过**（不注册任何自定义 type） | ✅ **天然可过** |
| 内核审计事件 | `/sys/fs/selinux/load` 被写 → audit/dmesg 有记录 | ❌ 保留（每次起 server 一次） | ✅ 消除（整段代码不存在） | ✅ 天然无 |

**一句话**：
- B 的对手是**名单式检测**（拿到样本后挖出来的特征串）—— 改名有效。
- 遇到**白名单式检测**（用 AOSP 基线做 policy diff，或校验 `security_load_policy` 调用）→ **B 无力**，此时只能上 **A**（且需 §6 两项实测通过）或 **gadget**。
- 所以三层场景表（§0）里 gadget 才是"结构性最优"：它连"自定义 type"这个类别都不产生，不是靠改名绕过。

---

## 5. A / B 选型矩阵

| 维度 | A（删注入） | B（改名） |
|---|---|---|
| 内核审计事件（`/sys/fs/selinux/load` 写入） | **消除** | 保留（每次起 server 一次） |
| 策略里可名单化的自定义 type | **消除**（0 个） | 保留（2 个，名字换了） |
| 载荷 `ls -Z` 自定义标签 | **消除**（用 stock type） | 保留（2 个新名） |
| `grep -a frida /sys/fs/selinux/policy` | **失效** | 失效（但 `diff` stock 策略仍可见） |
| attach 已运行 app | 押 AOSP 规则（§6-①） | 有保证 |
| `frida -f` / spawn-gating / zygote / system_server | **高风险失败** | 有保证 |
| 依赖风险3 协同 | 是（A6-A8 三个 hunk 在他的文件里） | 是（**共 9 处**：策略侧 5 处在本 patch、标签侧 4 处在他的文件，见 §4.2） |
| 回退成本 | 低（revert 一个 patch） | 低 |
| **定位（最终裁决）** | **待实测条件选项** | **默认方案** |

**结论**：默认位是 **B**。A 只有在 §6 的 ①（`execmem`）与 ②（`relabelto`）**都实测通过**后才能从条件选项转正；任一不通过即直接用 B。
（这里不采用"A 优先"的原因见 §0 与 §3.3 的功能代价表：A 把注入可行性从"我们自己保证"降级为"押注 AOSP 已给"。）

---

## 6. 待实测清单（方法 + 判定标准 + 预期结果）

> 全部**待授权后执行**。本节不含任何已执行的动作。命令里 `<pkg>` 是目标 app 包名。

### ① AOSP 是否已给目标域 `execmem`（决定 A 下 attach 是否可行）

**方法**
```bash
adb shell 'su -c "cat /sys/fs/selinux/policy"' > /tmp/pol        # 或 adb pull
# 宿主机上（需 policycoreutils / setools）：
sesearch --allow -s untrusted_app -t self -c process -p execmem /tmp/pol
# 目标域不是 untrusted_app 时，先取目标进程域：
adb shell "ps -Z | grep <pkg>"
```
**判定标准**
- 有 `allow untrusted_app self:process execmem;` 输出 → AOSP 已兜住，A 下 attach 的 `mprotect` 不会因 avc 被拒。
- 无输出 → A 下 attach **也会失败**（`execmem` denied）。

**预期结果（待实测确认）**：AOSP 通常会为 app 域保留 `execmem`（ART JIT 需要），因此预期**有输出**；但这只是推断，必须以 `sesearch` 结果为准。

### ② server 所在域是否允许 `relabelto` 目标 type（决定 A6-A8 是否真的生效）

**方法**
```bash
adb shell 'id -Z'                       # 看 frida-server 所在域，如 u:r:su:s0 / u:r:magisk:s0
adb shell 'ls -Z /data/local/tmp/'      # 基线：默认标签应为 shell_data_file
# 起 server 并触发一次载荷写入后：
adb shell 'ls -Z /data/local/tmp/<dir>/'         # 看 .so 的实际标签
adb shell 'ls -Z /data/local/tmp/<dir>'
adb shell 'dmesg | grep -i avc | tail -30'       # 或 logcat -b events -d | grep avc
```
**判定标准**
- `ls -Z` 显示 `u:object_r:app_data_file:s0` → relabel 成功，A6-A8 生效。
- `ls -Z` 仍是 `u:object_r:shell_data_file:s0`，且 `avc` 里有 `denied { relabelto }` → relabel 被拒，**A6-A8 无效**。
- 无论哪种，都要再验一次 `dlopen` 是否被拒（`avc ... denied { execute }`）。

**失败回退路径**（按代价从低到高）
1. 换候选 type：`system_file` → 再测一次 ②。
2. 改成「**不 relabel**」变体：删掉 A6/A7/A8 三个 hunk 的 `#if ANDROID` 块 → 零 SELinux 接触，只看 AOSP 是否放行 `shell_data_file:file execute`（同样用 `avc` 判定）。
3. 整体回退到 **B**（改名），放弃 A。

**预期结果（待实测确认）**：`su` / `magisk` 域通常有宽泛 relabel 权限，预期**成功**；但 `magisk` 的 sepolicy 注入方式因版本而异，不能当作既定事实。

### ③ 复用 type 后目标域是否能 `execute`（决定载荷能否加载）

**方法**
```bash
sesearch --allow -s untrusted_app -c file -p execute /tmp/pol | grep -E 'app_data_file|system_file|shell_data_file'
```
**判定标准**：出现对应 type 的 `execute` → 可加载；缺失 → 需换 type 或回退 B。

### ④ B 路线的改名有效性（改名后功能是否完好）

**方法**：`grep -rn 'frida_file\|frida_memfd\|sysd_file\|sysd_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala` ——
应得 **9 处 `sysd_*`、0 处 `frida_*`**（策略侧 5 + 标签侧 4）；设备侧 `ls -Z` 应显示 `u:object_r:sysd_file:s0`。

**判定标准**：9 处字符串完全一致（两侧同名）+ `ls -Z` 命中新名 → 通过。只改一侧 = 静默失败（§4.2）。
**预期结果**：改名不改语义，预期**通过**；唯一风险是人工漏改。

### ⑤ `patch.c:151-160` 的 `setenforce(0)` 兜底是否触发

**方法**：`dmesg | grep -i setenforce`、`dmesg | grep -i avc`（在 A 下这段代码已消失，此项仅用于 B 或未打补丁基线）。
**判定标准**：出现 `setenforce` 相关审计 → 兜底被触发过（意味着策略写入失败）。
**预期结果**：真机 + enforcing 下，正常 `su`/`magisk` 域**不应触发**；模拟器上可能触发（这也是 A 的额外收益：整段代码不存在了）。

---

## 7. Hunk 归属（避免与 @风险3 撞车）

| 文件 | 归谁 | 说明 |
|---|---|---|
| `server/server-glue.c` | 我（A1） | 调用点 |
| `inject/inject-glue.c` | 我（A2） | 调用点 |
| `lib/selinux/patch.c` | 我（A3 / **B 的 5 处**） | 补丁文本我出，**落地由风险3 执行** |
| `lib/selinux/meson.build` | 我（A4） | 编译单元 |
| `meson.build` | 我（A5） | 依赖声明 |
| `src/linux/linjector.vala` | **风险3**（A6/A7；**B 的 ⑥⑦⑧**） | 注入器侧；A 补丁里已含，可与 A1-A5 一起落地 |
| `lib/pipe/pipe.vala` | **风险3**（A8；**B 的 ⑨**） | 同上 |

### 7.1 B 路线交接（完整 9 处口径，直接转给风险3）

> 上一轮我在交付消息里把 B 写成"改 4 处"，**错了**：只改 label 4 处会把 label 指向从未被注入的 type → `setfilecon` 返 -1 → **静默失败**。正确口径是 **9 处**：

- **策略侧 5 处（①–⑤）**：`lib/selinux/patch.c` 的 `:42/:43/:85`（`frida_file`）+ `:44/:92`（`frida_memfd`）→ **由 `selinux-B-rename-types.patch` 覆盖，风险3 只管 apply**
- **标签侧 4 处（⑥–⑨）**：`src/linux/linjector.vala:268/275/281` + `lib/pipe/pipe.vala:172` → **由风险3 自行改**
- **两批必须同名**（`sysd_file` / `sysd_memfd`），否则整条注入链静默失效

**纯静态验收（不碰设备）**：
```bash
cd subprojects/frida-core
grep -n 'frida_file\|frida_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala   # 期望无输出
grep -n 'sysd_file\|sysd_memfd'  lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala   # 期望 9 行
```

### 7.2 A 路线交接（可与 A1-A5 拆开）

如果只需"我负责的 hunk"：A 补丁里 `linjector.vala` 与 `pipe.vala` 两个文件块在**文件末尾**，可用
`filterdiff -x 'a/src/linux/*' -x 'a/lib/pipe/*'` 摘掉，剩下的 A1-A5 独立自洽（`patch.c` 变 stub、调用点删除、依赖清理），不影响编译。
但注意：A 方案下若**只摘掉 A6–A8、保留旧 label**，会重现同一个静默失败模式（label 指向 `frida_file` 但 patch.c 已不注册该 type），所以 A1–A5 与 A6–A8 **要么一起上，要么一起不上**。

---

## 8. 回退

```bash
cd subprojects/frida-core
git apply -R _stealth/patches/selinux-A-remove-policy-injection.patch   # 或 B
git checkout -- lib/selinux src/linux/linjector.vala lib/pipe/pipe.vala meson.build
```

---

## 7.3 标签侧 4 处已单独成 patch（主线程补）

原 README 的 §4.2/§7.1 说明"标签侧 4 处由注入侧手改"。为避免手改遗漏，已把它固化成补丁文件：

`selinux-B2-label-sites.patch`
- `src/linux/linjector.vala:268` `:275` → `u:object_r:sysd_file:s0`
- `src/linux/linjector.vala:281` → `u:object_r:sysd_memfd:s0`
- `lib/pipe/pipe.vala:172` → `u:object_r:sysd_file:s0`

**B 方案 = B + B2 两个 patch 一起打**，缺一个就是静默失败。

端到端静态验证（已在钉定 commit 上跑过，未编译）：
```
git apply selinux-B-rename-types.patch   # 策略侧 5 处
git apply selinux-B2-label-sites.patch   # 标签侧 4 处
grep -rn 'sysd_file\|sysd_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala | wc -l   # → 9
grep -rn 'frida_file\|frida_memfd' lib/selinux/patch.c src/linux/linjector.vala lib/pipe/pipe.vala | wc -l  # → 0
```
三个 patch 文件的换行已统一为 LF（CRLF 会让 Linux 上的 `git apply` 失败）。
