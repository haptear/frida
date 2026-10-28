# 用 GitHub Actions 自动构建"魔改版 Frida"，并自动检查改没改干净

## 一句话回答你的问题

**可以。** 而且能做成一条流水线：

```
我的分析结果（_stealth/*.md + patches/*.patch）
        ↓ 大模型照着 patch 清单改代码
        ↓ 推到你的 GitHub fork
        ↓ Actions 自动：装 NDK → 编 frida-vala → 打 patch → 编 frida-server → 自动检查 → 给你下载链接
        ↓
   你下载"魔改版 frida-server"
        ↓
   最后一步只能人工：装到真机上跑，看还查不查得出来
```

## 有一件事必须先说清楚（很重要）

**GitHub Actions 能"构建"，但**不能**替你验证"检测不到"。**

原因很简单：Actions 的机器是普通的 Linux 虚拟机，不是安卓手机。而"能不能被检测到"这个问题，必须**在真机上、装着真实 App、以 root 跑**才能回答。

所以整条链分成两半：

| 环节 | 谁来做 | 能不能自动化 |
|---|---|---|
| 改代码、编译、出 frida-server 文件 | GitHub Actions | ✅ 全自动 |
| 检查"名字改干净了没有"（二进制里还有没有 `frida` 字样、导出符号改没改、SELinux type 名换没换） | GitHub Actions | ✅ 全自动（就是 `verify-static.sh`） |
| 检查"App 还查不查得出来"（读它自己的 maps、线程名、端口、崩溃栈） | **真机 + root** | ❌ 必须人工，或者用你自己的电脑当 runner |
| 检查"SELinux 那两条到底行不行"（`relabelto`、`execmem`） | **真机 + root** | ❌ 必须人工 |

最后两行就是我在分析里反复标"待实测"的东西。**CI 跑绿了，不等于魔改成功**，只等于"改的名字确实进了二进制"。

## 你需要做什么（3 步）

### 第 1 步：把东西推到你的 GitHub fork

```bash
# 在你的机器上，frida 源码目录里
cd D:/tools/apk-reverses/frida-mg

git add _stealth/
git commit -m "stealth: fingerprint analysis + patches + ci"
git push origin <你的分支>
```

然后把这两个文件放进仓库（路径不能错）：

```
.github/workflows/stealth-build.yml     ← 从 _stealth/ci/stealth-build.yml 复制过去
```

`_stealth/ci/verify-static.sh` 保持原地不动，workflow 会去调它。

### 第 2 步：在 GitHub 上点一下

仓库页面 → `Actions` → 左边选 `stealth-build` → 右边 **Run workflow**。

**不用选任何参数**——点一下就跑。固定内容是：

- 目标：**Android arm64**（`ANDROID_ABI: 'arm64'`，在文件顶部 env 里）
- 版本：`17.9.9`（同上）
- 改动：**names + selinux-B** 两组全打（名字全改 + SELinux 9 处改名）

> 想改 ABI 或版本，改 `stealth-build.yml` 顶部两行 env 即可；不需要在界面上选。

约 30–60 分钟后跑完（第一次要编 frida-vala，最慢；之后有缓存会快很多）。

### 第 3 步：下载产物 + 看检查表

跑完后页面底部有两样东西：

1. **Artifacts** → 下载 `stealth-android`（zip 名是 `frida-stealth-17.9.9-android-arm64.zip`），里面是 `sysd`（改过名后的 server）+ `frida-gadget.so` + `USE.txt`
2. **Job Summary** → 里面是自动检查的结果表，大概是这个样子：

```
[PASS] ELF 架构 = AArch64
[PASS] 无禁用字符串残留（frida-agent frida-server ... gum-js-loop re.frida）
[PASS] 无 u:object_r:frida_* 残留
[PASS] 新 SELinux type 命中： sysd_file sysd_memfd
[PASS] 无 frida_agent_main 导出残留
[WARN] 存在 .comment 段（暴露编译器版本，建议 strip 掉）
```

全是 PASS 就说明"名字层面改干净了"。有一个 FAIL 就说明某个 patch 没生效，去对应那行看提示。

## 打包产物长什么样（都在 runner 上生成，本机什么都不用装）

跑完以后你会拿到一个 zip，解开是这样：

```
frida-server-17.9.9-android-arm64-stealth-selinux-B-rename-types/
├── frida-server          ← 魔改后的服务端（arm64）
├── frida-gadget.so       ← 顺带带上，方便走 gadget 路线
└── USE.txt               ← 怎么推到手机、怎么连、端口怎么设
frida-server-....zip
SHA256SUMS                ← 校验和
```

`USE.txt` 里已经写好了实际命令，核心两条：

```bash
adb push frida-server /data/local/tmp/.s
adb shell "su -c 'setsid /data/local/tmp/.s -l 127.0.0.1:53311 -d /data/local/tmp/.s.d >/dev/null 2>&1 </dev/null &'"
# 电脑端
adb forward tcp:53311 tcp:53311
frida -H 127.0.0.1:53311 -f <包名> -l script.js
```

注意两件事：
1. **端口用 `-l` 改成非默认值**（这里示例 53311），这样 27042 那条指纹天然消失，不用改代码。
2. 电脑端 `frida` 的版本要和包里的 server 一致，否则会报 `unexpected message`。

产物只出 Actions Artifact（zip + `SHA256SUMS` + `verify.log`），不自动发 Release。想要 Release 附件，下载后手工上传即可（少一层权限，也少一类出错点）。

## 关键名词（大白话）

| 名词 | 大白话 |
|---|---|
| **patch** | 一个文本文件，里面写"把第几行改成什么"。`git apply` 就是照着它改代码 |
| **NDK** | 安卓的编译器工具包。Frida 要求必须是 **r29** 这个版本，别的版本会直接报错 |
| **frida-vala** | Frida 用的一个特殊编译器（上游改过的 Vala）。官方要求版本号带 `-frida`，所以 CI 里要先自己编一个 |
| **artifact** | Actions 跑完后吐出来的文件（这里就是我们编好的 frida-server） |
| **静态检查** | 不运行程序，只看文件内容和二进制内容。能查"有没有 frida 字样"，查不了"运行时会怎样" |
| **闭环** | 改 → 编 → 查 → 出结果，四步都自动串起来，不用人中间插手 |

## 为什么 CI 里要自己编 frida-vala

因为 `subprojects/frida-core/meson.build` 第 11–19 行有这么一段：

> 如果 valac 版本号不是以 `-frida` 结尾，就直接 `error()` 拒绝配置。

这是硬门槛，绕不过去。所以 workflow 里专门有一步：clone `github.com/frida/vala` → 用 meson 编 → 装到临时目录 → 加到 PATH。这一步我加了缓存，第二次跑就不用重编。

## 更省事的替代方案（P2，值得考虑）

上面这条路要改 `frida-core`（Vala 写的），所以得先编 frida-vala，麻烦且慢。

另一条路是**只改 frida-gum（纯 C），自己写一个小 agent**，不碰 frida-core：

- 好处：**完全不需要 vala**，CI 干净很多；而且顺手就把 `frida-server` 进程、27042 端口、D-Bus、helper 进程这四大指纹全砍掉了（因为根本没这些东西了）
- 代价：要自己写一个几十行的 `agent.c`，还要自己定一个和电脑端通信的小协议

这条路的骨架代码在 `02-魔改方案与验收.md` 的 §3.3，如果你想先看这条路，我可以直接把可编译的 `agent.c` + `meson.build` 写出来，同样能用 Actions 编。

## 文件清单

| 文件 | 是什么 |
|---|---|
| `stealth-build.yml` | GitHub Actions 的流程定义（改代码 → 编译 → 检查 → 上传） |
| `verify-static.sh` | 自动检查脚本（"闭口检查"就靠它） |
| `README.md` | 本文 |

## 老实说的话

- 这个 workflow **我没有实际跑过**（本轮只做分析，没推仓库、没跑 CI）。三个最可能出问题的地方我写在 yml 文件头部了。
- 第一次跑失败很正常，通常是 vala 分支名或产物路径对不上，看报错改一行就行。
- **别把"CI 绿灯"当成"魔改成功"**。真正的判定标准只有一个：在真机上装好、跑目标 App、看它有没有反应。

---

## 附：两个最常被问到的问题

### 1. 打包后运行的二进制叫什么？

取决于你打了哪组：

| 打的组 | 构建出的二进制名 | 推到手机后 `ps` 里看到的名字 |
|---|---|---|
| `none` | `frida-server` | 你部署成什么名，就是什么名 |
| `names` / `names+selinux-B` | **`sysd`**（改了 `server/meson.build:44` 的 `server_name`） | 同上 |

**关键点：进程名 = 文件名（basename），不是编译进二进制的。** server 源码里没有 `prctl(PR_SET_NAME)`，`g_set_prgname` 也只在 agent 侧（gum）出现过，所以：

```bash
adb push sysd /data/local/tmp/.s      # 文件名变成 .s
adb shell "su -c 'setsid /data/local/tmp/.s ... &'"
adb shell "ps -A -o PID,NAME" | grep -F '.s'    # 看到的是 .s，不是 sysd，也不是 frida
```

`USE.txt` 里就是这么写的，所以**哪怕你打了 `none` 组，改部署名也能让进程名不叫 frida-server**。

### 2. "grep frida 字样"到底查什么、怎么过？

要分别看三个地方：

| 查的地方 | 命令 | 对策 | CI 能验吗 |
|---|---|---|---|
| 进程名 | `ps -A -o NAME` | 部署时改名（`/data/local/tmp/.s`） | ❌ 真机 |
| **二进制内容** | `adb shell "strings /data/local/tmp/.s \| grep -i frida"` | 打 `names` 组（改掉 `frida-server`、`frida-agent-<arch>`、`re.frida.*`、`gum-js-loop`、`Frida/` UA 等） | ✅ 静态可验 |
| 运行时的 maps | `cat /proc/<pid>/maps` | 打 `names` 组后 agent 的 memfd 名变成 `libm-64.so` | ❌ 真机 |

**改不掉的（诚实说明）：**

1. `frida_agent_main` 这个导出符号，由 Vala 命名空间 `Frida.Agent`（`lib/agent/agent.vala:3`）决定。改名等于重命名整个命名空间，风险大，本轮**没做**。所以 `strings <agent.so> | grep frida_agent_main` 仍会命中。
2. `frida:rpc` 是 agent ↔ 电脑端的协议前缀，改它要**电脑端一起改**（要重新编 frida-python），默认不动。
3. QuickJS 引擎自身的标识属于"任何 JS 引擎都会被认得"的那一类，不在"grep frida"范围内，但强风控会查。

`verify-static.sh` 对第 1 项只报 **WARN 并写明原因**，不伪造绿灯。

---

## 重要：改了前缀的两端耦合

`names` 组会改两处「两端协议」：

1. D-Bus 名族 `re.frida.*` → `io.sysd.*`
2. RPC 前缀 `frida:rpc` → `sysd:rpc`

**所以打了 `names` 以后，pip 装的 `frida` 连不上我们的服务端**（报 handshake / unexpected message）。这是协议不匹配，不是 bug。

两个解法：

- 跑 `ci/host-build.yml`（同样无参数，打同一组 patch），用产出的同源 CLI 去连；
- 或者选不含 `names` 的组（例如只用 `selinux-B`），这时 pip 的 frida 可以正常用。

完整风险点归属见 `../03-风险点闭环清单.md`。
