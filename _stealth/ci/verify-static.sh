#!/usr/bin/env bash
# verify-static.sh —— 魔改 Frida 产物的「静态闭环检查」
#
# 用途：在 CI 里自动判定"补丁是否真的生效、二进制里还有没有残留指纹"。
# 特点：不需要真机、不需要模拟器、不需要 root。全部是静态判定。
#
# 用法：
#   ./verify-static.sh <产物文件> [产物文件...]
#   ./verify-static.sh _out/bin/frida-server _out/lib/frida-1.0/64/frida-gadget.so
#
# 退出码：0 = 全部通过；1 = 有 FAIL。
#
# 注意：本脚本只能证明"名字层面改了"，**证明不了"运行时检测不到"**。
#      运行时（maps / 线程名 / 端口 / AVC / 崩溃栈）必须真机，见 README。

set -uo pipefail

FAIL=0
WARN=0

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_off=$'\033[0m'
pass() { printf '%s[PASS]%s %s\n' "$c_grn" "$c_off" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }
warn() { printf '%s[WARN]%s %s\n' "$c_yel" "$c_off" "$*"; WARN=$((WARN+1)); }

if [ $# -eq 0 ]; then
  echo "usage: $0 <artifact> [artifact...]" >&2
  exit 2
fi

# ---------------------------------------------------------------- 期望值
# 如果你在 patch 里换了别的名字，改这三行即可（与 patches/README.md 的 9 处口径一致）
EXPECT_AGENT_NAME="${EXPECT_AGENT_NAME:-libm-64.so}"     # agent 资源名（names-core.patch 后；原 frida-agent-64.so）
EXPECT_SELINUX_TYPES="${EXPECT_SELINUX_TYPES:-sysd_file sysd_memfd}"
FORBIDDEN_STRINGS="${FORBIDDEN_STRINGS:-frida-server frida-gadget frida-helper frida:rpc gum-js-loop re.frida}"

check_one() {
  local f="$1"
  echo
  echo "=== $(basename "$f") ==="

  if [ ! -f "$f" ]; then
    fail "文件不存在：$f"
    return
  fi

  # 0) 是真 ELF 吗
  local machine
  machine=$(readelf -h "$f" 2>/dev/null | awk -F: '/Machine:/{gsub(/^ +/,"",$2); print $2}')
  if [ -z "$machine" ]; then
    fail "不是有效 ELF（readelf 失败）"
    return
  fi
  case "$machine" in
    *AArch64*) pass "ELF 架构 = $machine" ;;
    *)         warn "ELF 架构 = $machine（预期 AArch64，若是别的 ABI 请确认）" ;;
  esac

  # 1) 禁止字符串残留（改名是否真的落到二进制里）
  local hits
  hits=$(strings -a "$f" | grep -Eo "$(echo $FORBIDDEN_STRINGS | tr ' ' '|')" | sort -u | tr '\n' ' ')
  if [ -z "$hits" ]; then
    pass "无禁用字符串残留（$FORBIDDEN_STRINGS）"
  else
    fail "仍有禁用字符串：$hits"
  fi

  # 2) SELinux 自定义 type：旧名必须消失
  if strings -a "$f" | grep -q 'u:object_r:frida_'; then
    fail "仍有 u:object_r:frida_*（label 未改完）"
  else
    pass "无 u:object_r:frida_* 残留"
  fi
  # 新名是否出现（只有包含策略侧/标签侧代码的产物才会有）
  local found_types="" t
  for t in $EXPECT_SELINUX_TYPES; do
    if strings -a "$f" | grep -q "$t"; then found_types="$found_types $t"; fi
  done
  if [ -n "$found_types" ]; then
    pass "新 SELinux type 命中：$found_types"
  else
    warn "未找到新 SELinux type（若该产物不含 selinux 代码则正常；server 产物必须命中）"
  fi

  # 3) 导出符号：应已改名为 sysd_agent_main（names-core.patch）
  if nm -D --defined-only "$f" 2>/dev/null | grep -q 'frida_agent_main'; then
    fail "导出符号 frida_agent_main 仍在（names-core.patch 未生效：Vala 命名空间 + 12 处引用 + 5 处 entrypoint 字符串）"
  else
    pass "无 frida_agent_main 残留"
  fi
  if nm -D --defined-only "$f" 2>/dev/null | grep -q 'sysd_agent_main'; then
    pass "导出符号 sysd_agent_main 存在"
  fi

  # 3b) agent 资源名（memfd 名）是否已改
  if strings -a "$f" | grep -q 'frida-agent-<arch>'; then
    fail "agent 资源名模板仍是 frida-agent-<arch>.so（names-core.patch 未生效）"
  else
    pass "agent 资源名模板已改（期望 $EXPECT_AGENT_NAME）"
  fi

  # 3c) RPC 前缀（names-core / names-gum 里的 frida:rpc -> sysd:rpc）
  if strings -a "$f" | grep -q 'frida:rpc'; then
    fail "仍有 frida:rpc（rpc.vala / gumjs runtime 未改完）"
  else
    pass "无 frida:rpc 残留"
  fi

  # 4) 版本/构建指纹：.comment 段（暴露 NDK/clang 版本）
  if readelf -S "$f" 2>/dev/null | grep -q '\.comment'; then
    warn "存在 .comment 段（暴露编译器版本，建议 strip 掉）"
  else
    pass "无 .comment 段"
  fi

  # 5) 体积与哈希（用于和基线对比，本身不判定）
  local size; size=$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")
  printf '       size=%s bytes  sha256=%s\n' "$size" "$(sha256sum "$f" | cut -c1-16)"

  # 6) 动态段里是否还链着奇怪的库（信息性）
  readelf -d "$f" 2>/dev/null | awk '/NEEDED/{print "       NEEDED:" $NF}' | head -8
}

for a in "$@"; do check_one "$a"; done

echo
echo "================ 汇总 ================"
if [ "$FAIL" -eq 0 ]; then
  printf '%s静态闭环检查通过%s（warn=%d）\n' "$c_grn" "$c_off" "$WARN"
  echo "下一步（必须真机，CI 做不了）："
  echo "  adb shell \"ls /proc/<pid>/task | while read t; do cat /proc/<pid>/task/\$t/comm; done\" | sort -u"
  echo "  adb shell \"cat /proc/<pid>/maps\" | grep -Ei 'frida|gum|gadget|memfd'"
  echo "  adb shell \"cat /proc/net/tcp\" | grep -Ei '69A2|69AC'"
  echo "  adb shell \"grep -a frida /proc/net/unix\""
  exit 0
else
  printf '%s静态闭环检查失败%s：%d 项 FAIL\n' "$c_red" "$c_off" "$FAIL"
  exit 1
fi
