#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
frida-core 控制面（control plane）可检测特征消除 —— 确定性打补丁脚本
目标 commit: frida-core 61708ddb0c8f55eaf363385d8647c9a385660fa5

用法:
    python apply-dedetect.py --root <frida-core 根目录>            # 干跑，只报告
    python apply-dedetect.py --root <frida-core 根目录> --apply    # 实际写入
    python apply-dedetect.py --root <...> --apply --host-side      # 额外打 host 侧指纹

设计原则:
  * 每条替换都带"期望命中次数"，命中数不符 → 整批中止（不改任何文件），
    避免上游漂移后静默打歪。
  * 幂等：已打过的项命中 0 次且新串已存在 → 记为 already-applied 跳过。
  * 文件按二进制读写，保留原换行（src/android-helper/Makefile 是 CRLF）。
"""

import argparse
import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 命名空间（按需改这里，全量补丁自动跟随）
# ---------------------------------------------------------------------------
NEW_DBUS_IFACE_PREFIX = "io.sysd."          # 原 "re.frida."
NEW_DBUS_PATH_PREFIX = "/io/sysd/"          # 原 "/re/frida/"
NEW_DBUS_GUID = "a3f19c2e5b7d40819e6f2c4d7a1b8e03"  # 原 6769746875622e636f6d2f6672696461 (= "github.com/frida")

NEW_JAVA_PKG = "io.sysd"                    # 原 re.frida
NEW_JAVA_PKG_PATH = "io/sysd"               # 原 re/frida

NEW_SERVER_DIR = ".sysd"                    # 原 re.frida.server
NEW_HELPER_PREFIX = ".sysdh"                # 原 frida-helper  (文件 / 抽象 socket / nice-name)
NEW_HELPER_NICENAME = "sysdh"               # 原 re.frida.helper

NEW_GADGET_IDENTIFIER = "io.sysd.Gadget"    # 原 re.frida.Gadget
NEW_GADGET_NAME = "sysd"                    # 原 "Gadget"
NEW_GADGET_LIB = "libsysd"                  # 原 frida-gadget

NEW_CONTROL_PORT = 47001                    # 原 27042
NEW_CLUSTER_PORT = 47002                    # 原 27052

# SELinux（G 组）已移交风险3，见 D:/tools/apk-reverses/frida-mg/_stealth/patches/

# ---------------------------------------------------------------------------
# (相对路径, 旧串, 新串, 期望命中次数)
# ---------------------------------------------------------------------------
EDITS = [
    # ===== A. 端口（lib/base/socket.vala:4-5）=====
    ("lib/base/socket.vala",
     "public const uint16 DEFAULT_CONTROL_PORT = 27042;",
     f"public const uint16 DEFAULT_CONTROL_PORT = {NEW_CONTROL_PORT};", 1),
    ("lib/base/socket.vala",
     "public const uint16 DEFAULT_CLUSTER_PORT = 27052;",
     f"public const uint16 DEFAULT_CLUSTER_PORT = {NEW_CLUSTER_PORT};", 1),

    # ===== B. D-Bus 名族 =====
    # B1 接口名 13 处：session.vala:4,51,66,110,131,759,787,794,804,810,819,826 + Error:1222
    ("lib/base/session.vala", '"re.frida.', f'"{NEW_DBUS_IFACE_PREFIX}', 13),
    # B2 对象路径 12 处：session.vala:2785-2796
    ("lib/base/session.vala", '"/re/frida/', f'"{NEW_DBUS_PATH_PREFIX}', 12),
    # B3 D-Bus server GUID：session.vala:2781，hex 解出来是 "github.com/frida"
    ("lib/base/session.vala",
     '"6769746875622e636f6d2f6672696461"',
     f'"{NEW_DBUS_GUID}"', 1),

    # ===== C. server 默认目录（server/server.vala:6）=====
    ("server/server.vala",
     'private const string DEFAULT_DIRECTORY = "re.frida.server";',
     f'private const string DEFAULT_DIRECTORY = "{NEW_SERVER_DIR}";', 1),

    # ===== D. Android helper =====
    # D1 宿主机侧（走 adb + app_process）
    ("src/android-helper/client.vala",
     "/data/local/tmp/frida-helper-",
     f"/data/local/tmp/{NEW_HELPER_PREFIX}-", 1),
    ("src/android-helper/client.vala",
     "--nice-name=re.frida.helper re.frida.Helper %s",
     f"--nice-name={NEW_HELPER_NICENAME} {NEW_JAVA_PKG}.Helper %s", 1),
    ("src/android-helper/client.vala",
     '"localabstract:/frida-helper-" + instance_id',
     f'"localabstract:/{NEW_HELPER_PREFIX}-" + instance_id', 1),
    # D2 设备侧（frida-server 自己起 JavaVM，linux-host-session.vala:486 / :747）
    ("src/linux/linux-host-session.vala",
     "/data/local/tmp/frida-helper-",
     f"/data/local/tmp/{NEW_HELPER_PREFIX}-", 1),
    ("src/linux/linux-host-session.vala",
     '"re/frida/HelperBackend"',
     f'"{NEW_JAVA_PKG_PATH}/HelperBackend"', 1),
    # D3 frida-server 内线程名（/proc/<pid>/task/<tid>/comm 可见）
    ("src/linux/linux-host-session.vala",
     'new Thread<void> ("frida-android-helper", run)',
     f'new Thread<void> ("{NEW_HELPER_NICENAME}", run)', 1),
    # D4 helper.dex 的 Java 源（改包名 → 必须重建 dex）
    ("src/android-helper/re/frida/Helper.java",
     "package re.frida;", f"package {NEW_JAVA_PKG};", 1),
    ("src/android-helper/re/frida/Helper.java",
     '/data/local/tmp/frida-helper-" + instanceId',
     f'/data/local/tmp/{NEW_HELPER_PREFIX}-" + instanceId', 1),
    ("src/android-helper/re/frida/Helper.java",
     'new LocalServerSocket("/frida-helper-" + instanceId)',
     f'new LocalServerSocket("/{NEW_HELPER_PREFIX}-" + instanceId)', 1),
    ("src/android-helper/re/frida/Helper.java",
     '"Usage: frida-helper <instance-id>"',
     f'"Usage: {NEW_HELPER_NICENAME} <instance-id>"', 1),
    ("src/android-helper/re/frida/HelperBackend.java",
     "package re.frida;", f"package {NEW_JAVA_PKG};", 1),
    ("src/android-helper/Makefile",
     "build/frida-helper.jar: re/frida/Helper.java re/frida/HelperBackend.java",
     f"build/frida-helper.jar: {NEW_JAVA_PKG_PATH}/Helper.java {NEW_JAVA_PKG_PATH}/HelperBackend.java", 1),
    ("src/android-helper/Makefile",
     "jar cfe $@ re.frida.Helper -C build/java/ .",
     f"jar cfe $@ {NEW_JAVA_PKG}.Helper -C build/java/ .", 1),

    # ===== E. Gadget =====
    ("lib/gadget/gadget.vala",
     'string identifier = "re.frida.Gadget";',
     f'string identifier = "{NEW_GADGET_IDENTIFIER}";', 1),
    ("lib/gadget/gadget.vala",
     'string name = "Gadget";',
     f'string name = "{NEW_GADGET_NAME}";', 1),
    ("src/droidy/droidy-host-session.vala",
     'private const string GADGET_APP_ID = "re.frida.Gadget";',
     f'private const string GADGET_APP_ID = "{NEW_GADGET_IDENTIFIER}";', 1),
    # 444 行用的是字面量，不是常量 —— 顺手归一化，避免漏改
    ("src/droidy/droidy-host-session.vala",
     'if (identifier == "re.frida.Gadget")',
     "if (identifier == GADGET_APP_ID)", 1),
    ("src/fruity/fruity-host-session.vala",
     'private const string GADGET_APP_ID = "re.frida.Gadget";',
     f'private const string GADGET_APP_ID = "{NEW_GADGET_IDENTIFIER}";', 1),
    # 产物名 libfrida-gadget.so → libsysd.so
    ("meson.build",
     "gadget_name = 'frida-gadget' + shlib_suffix",
     f"gadget_name = '{NEW_GADGET_LIB}' + shlib_suffix", 1),

    # ===== G. SELinux 类型名 —— 【已从本脚本移除】=====
    # 裁决变更（叮叮，sequence 14 + 19）：G 组归 @风险3，本脚本不再触碰
    #   lib/selinux/patch.c / src/linux/linjector.vala / lib/pipe/pipe.vala
    # 改由两套独立 patch 承担，见 D:/tools/apk-reverses/frida-mg/_stealth/patches/
    #   selinux-A-remove-policy-injection.patch   （首选：删策略注入 + 复用已有 type）
    #   selinux-B-rename-types.patch              （回退：类型改名）
    # 两者互斥，请勿叠加，也请勿再回到本脚本打 G 组。
]

# host 侧额外指纹（host→device 的 WS 握手），设备侧抓不到，只有抓包/L3 hook 能看见
HOST_SIDE_EDITS = [
    # Host: lolcathost  —— lib/base/socket.vala:255 用 host 参数拼 Host 头
    ("src/droidy/droidy-host-session.vala", '"lolcathost"', '"localhost"', 2),
    ("src/fruity/fruity-host-session.vala", '"lolcathost"', '"localhost"', 2),
    ("src/socket/socket-host-session.vala", '"lolcathost"', '"localhost"', 1),
    ("lib/gadget/gadget.vala", '"lolcathost"', '"localhost"', 1),
    # User-Agent: Frida/<ver> —— lib/base/socket.vala:255
    ("lib/base/socket.vala",
     'msg.request_headers.replace ("User-Agent", "Frida/" + _version_string ());',
     'msg.request_headers.replace ("User-Agent", "Mozilla/5.0 (Linux; Android 14)");', 1),
]

# 目录移动（改 Java 包名的物理前提）
MOVES = [
    ("src/android-helper/re/frida", f"src/android-helper/{NEW_JAVA_PKG_PATH}"),
]


def read_bytes(p: Path) -> bytes:
    return p.read_bytes()


def resolve(root: Path, rel: str) -> Path:
    """目录已移动过（二次运行）时，自动映射到新路径。"""
    p = root / rel
    if p.exists():
        return p
    for src_rel, dst_rel in MOVES:
        if rel.startswith(src_rel + "/"):
            p2 = root / (dst_rel + rel[len(src_rel):])
            if p2.exists():
                return p2
    return p

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="frida-core 仓库根目录")
    ap.add_argument("--apply", action="store_true", help="实际写入（默认干跑）")
    ap.add_argument("--host-side", action="store_true", help="同时打 host 侧握手指纹")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not (root / "lib/base/session.vala").exists():
        print(f"[FATAL] {root} 看起来不是 frida-core 根目录", file=sys.stderr)
        return 2

    edits = list(EDITS) + (list(HOST_SIDE_EDITS) if args.host_side else [])

    # ---------- pass 1: 预检 ----------
    planned, already, failures = [], [], []
    for rel, old, new, expect in edits:
        p = resolve(root, rel)
        if not p.exists():
            failures.append((rel, "missing-file", 0, expect))
            continue
        data = read_bytes(p).decode("utf-8")
        n_old = data.count(old)
        n_new = data.count(new)
        if n_old == expect:
            planned.append((rel, old, new, expect))
        elif n_old == 0 and n_new >= 1:
            already.append((rel, old, new))
        else:
            failures.append((rel, f"hits={n_old}", n_old, expect))

    print("=" * 78)
    print(f"root        : {root}")
    print(f"mode        : {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"host-side   : {args.host_side}")
    print(f"planned     : {len(planned)}")
    print(f"already     : {len(already)}")
    print(f"failures    : {len(failures)}")
    print("=" * 78)
    for rel, old, new, expect in planned:
        print(f"  + {rel:52s} x{expect}")
    for rel, old, new in already:
        print(f"  = {rel:52s} already-applied")
    for rel, why, got, expect in failures:
        print(f"  ! {rel:52s} {why} (expect {expect})", file=sys.stderr)

    if failures:
        print("\n[ABORT] 有替换未按预期命中，未修改任何文件。", file=sys.stderr)
        print("        上游可能已漂移，请复查 01-PATCH-LIST.md 里的 file:line。", file=sys.stderr)
        return 1

    if not args.apply:
        print("\n干跑结束。加 --apply 实际写入。")
        return 0

    # ---------- pass 2: 写入 ----------
    for rel, old, new, expect in planned:
        p = resolve(root, rel)
        raw = read_bytes(p)
        text = raw.decode("utf-8")
        assert text.count(old) == expect
        raw_new = text.replace(old, new).encode("utf-8")
        p.write_bytes(raw_new)

    # ---------- pass 3: 目录移动 ----------
    for src_rel, dst_rel in MOVES:
        src, dst = root / src_rel, root / dst_rel
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            # 清掉移动后留下的空壳目录（re/）
            parent = src.parent
            guard = root / "src/android-helper"
            while parent != guard and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
            print(f"  > moved {src_rel} -> {dst_rel}")

    print("\n[OK] 补丁已写入。下一步：")
    print("  1) 若打了 D4（Java 包名），必须重建 helper.dex：")
    print("     cd src/android-helper && make            # 需要 android.jar + d8")
    print("  2) 用 strings 复核二进制里没有残留：见 03-BUILD-VERIFY.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
