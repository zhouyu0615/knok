#!/usr/bin/env bash
# knok M2 端到端验收（在 Linux VPS 上以 root 运行：`sudo make e2e`）。
#
# 场景：用 nftables 的 inet knok 表保护 lo 上的 TCP 22222（一次性 nc 监听器），
# SPA 走 UDP 4242，逐步验证：
#
#   step 0 监听器可用：没有防火墙时探测必须成功（证明 22222 确实在听）
#   step 1 基线：knokd 装上 drop 规则后，受保护端口**静默丢弃**（探测超时，
#          而不是 connection refused——RST 会泄漏端口存在）
#   step 2 敲门：`knok auth` 后端口在轮询窗口内打开
#   step 3 TTL 到期：端口重新关闭
#   step 4 重启存活：再次敲门 + 杀掉/重启守护进程，授权不中断
#          （pinned allowlist map + pinned TCX link 的语义）
#   step 5 逃生通道：第二份配置带 safety.admin_allow，不敲门也打开，
#          且未被覆盖的源地址仍被 drop（反证 drop 规则确实在生效）
#   cleanup 收尾：不留守护进程、不留 inet knok 表、不留 /sys/fs/bpf 下的 pin、
#          不留临时文件
#
# 三条设计要点（前两条来自一次手工验收的真实教训）：
#
#   1. 进程卫生：守护进程的关闭语义本身是 fail-closed（eBPF 附着与 nft 表都留在
#      内核里），所以"脚本退出"从来不等于"机器干净"。这里 trap EXIT/INT/TERM，
#      先杀掉本次启动的每一个进程（knokd、监听器的 nc 子进程），再按标记兜底清理，
#      然后 `-uninstall` 拆表/摘附着/删 pin，最后删掉自己的临时目录。手工那次泄漏
#      的正是监听器循环的 nc 子进程（杀 subshell 不会杀到它），泄漏的 nc 持有
#      22222，下一次运行会直接失真。
#   2. 断言确定性：每次状态变化都用**有界轮询**（100ms 步进，上限几秒）等目标
#      状态出现，超时即失败并打印实际观察到的状态，绝不 sleep 固定时长后假设结果。
#   3. 静默丢弃的判据是"探测超时"而不是"连接被拒绝"：nc -z 的两种失败都是 rc=1
#      且不打印原因，所以用**耗时**区分（≥1.5s = 被 drop 掉了 SYN）。
#
# 这台机器上的资源归本脚本独占：inet knok 表、TCP 22222、UDP 4242、
# /sys/fs/bpf/knok-e2e、以及带 knok-e2e 标记的进程。开始前会把这些残留清干净。
# 只用 SSH 别名/本机路径，不写任何主机名、账号或凭据。
set -euo pipefail

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
PORT=22222              # 受保护的 TCP 端口（nc 监听）
SPA_PORT=4242           # SPA UDP 端口
TTL=5                   # step 2/3 的授权 TTL（秒）
LONG_TTL=60             # step 4 的授权 TTL（秒，须 ≤ 配置里的 max_ttl）
DST=127.0.0.1           # 探测目标
FOREIGN_SRC=127.0.0.2   # step 5 的反证源地址：同属 127.0.0.0/8，但不在 admin_allow 里
PROBE_WAIT=2            # nc -z -w 的秒数
OPEN_BUDGET=6           # 等待"打开"的秒数预算（每次失败探测本身就要 PROBE_WAIT）
RUN_MARK=knok-e2e               # 临时路径标记：用来识别本次运行自己的进程/文件
LISTEN_MARK=knok-e2e-listener   # 监听器 nc 的 argv[0] 标记（pgrep -f 精确匹配）
LOOP_MARK=knok-e2e-loop         # 监听器循环进程的标记（argv 参数，仅用于识别）
PIN_DIR=/sys/fs/bpf/$RUN_MARK

WORK=""            # 临时目录（mktemp -d），cleanup 里删掉
CFG_SIMPLE=""      # 无逃生通道的配置
CFG_ADMIN=""       # 带 safety.admin_allow 的配置
BIN=""             # 构建产物目录（在 $WORK 里，不脏仓库）
PSK=""

DAEMON_PID=""      # 当前守护进程
DAEMON_LOG=""      # 当前守护进程日志
DAEMON_STARTED=0   # 启动过几次（cleanup 据此决定是否需要 -uninstall）
LISTENER_PID=""    # 监听器循环（subshell）
PRE_TC=""          # 运行前的 tc ingress 快照（收尾时对比）

FAILED=0           # 任一步失败
CLEAN_FAIL=0       # 收尾核查失败
RESULTS=()         # 逐条 PASS/FAIL，最后汇总

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
now_ms() { date +%s%3N; }

step() { printf '\n== %s\n' "$1"; }

pass() { printf 'PASS  %s\n' "$1"; RESULTS+=("PASS  $1"); }

fail() { printf 'FAIL  %s\n' "$1"; RESULTS+=("FAIL  $1"); FAILED=1; }

print_daemon_log() {
  printf -- '--- knokd log tail (%s) ---\n' "${DAEMON_LOG:-<none>}"
  if [ -n "$DAEMON_LOG" ] && [ -f "$DAEMON_LOG" ]; then
    tail -n 25 "$DAEMON_LOG" || true
  fi
  printf -- '--- end log ---\n'
}

# die 记录失败、打印守护进程日志尾部与当前观察到的状态，然后以非零退出。
# 退出会触发 EXIT trap（cleanup），所以失败路径同样会回收干净。
die() {
  fail "$1"
  shift || true
  print_daemon_log
  printf 'observed: probe(default)=%s probe(%s)=%s allow_hit=%s\n' \
    "$(probe)" "$FOREIGN_SRC" "$(probe "$FOREIGN_SRC")" "$(allow_hit_or_na)"
  exit 1
}

# ---------------------------------------------------------------------------
# 探测：open / refused / timeout
#   open    = TCP 三次握手成功（授权生效 + 监听器在听）
#   refused = 立刻 RST（端口上没人听，且没有 drop 规则——说明表没了）
#   timeout = SYN 被静默丢弃（nft drop 在生效）
# 两种失败 nc -z 都只给 rc=1、不打印原因，故用耗时区分。
# ---------------------------------------------------------------------------
probe() {
  local src="${1:-}" t0 t1 rc=0 ms
  t0=$(now_ms)
  if [ -n "$src" ]; then
    nc -z -w"$PROBE_WAIT" -s "$src" "$DST" "$PORT" >/dev/null 2>&1 || rc=$?
  else
    nc -z -w"$PROBE_WAIT" "$DST" "$PORT" >/dev/null 2>&1 || rc=$?
  fi
  t1=$(now_ms)
  ms=$((t1 - t0))
  if [ "$rc" -eq 0 ]; then
    printf 'open\n'
  elif [ "$ms" -ge 1500 ]; then
    printf 'timeout\n'   # 探测窗口内没有任何回应 = 被 drop
  else
    printf 'refused\n'
  fi
}

# wait_for_state <expected> <budget_seconds> <description> [src]
# 有界轮询：先探测再判断，最多等 budget 秒（100ms 步进）。失败时返回 1，
# 调用方负责用 LAST_PROBE 报告实际状态。
LAST_PROBE=""
wait_for_state() {
  local want="$1" budget="$2" desc="$3" src="${4:-}"
  local deadline got
  deadline=$(( $(now_ms) + budget * 1000 ))
  while :; do
    got=$(probe "$src")
    LAST_PROBE="$got"
    if [ "$got" = "$want" ]; then
      return 0
    fi
    if [ "$(now_ms)" -ge "$deadline" ]; then
      printf 'wait_for_state: %s: wanted %s, last observed %s after %ss\n' \
        "$desc" "$want" "$got" "$budget"
      return 1
    fi
    sleep 0.1
  done
}

# wait_for_log <file> <pattern> <budget_seconds>
# 用日志里的"最后一步完成"标记判定守护进程已经就绪——比监听端口更确定，
# 且不依赖额外的网络客户端。进程已死时立刻返回失败（不会再出现新日志）。
wait_for_log() {
  local f="$1" pat="$2" budget="$3"
  local deadline
  deadline=$(( $(now_ms) + budget * 1000 ))
  while :; do
    if [ -f "$f" ] && grep -q -- "$pat" "$f" 2>/dev/null; then
      return 0
    fi
    if [ -n "$DAEMON_PID" ] && ! kill -0 "$DAEMON_PID" 2>/dev/null; then
      return 1
    fi
    if [ "$(now_ms)" -ge "$deadline" ]; then
      return 1
    fi
    sleep 0.1
  done
}

# allow_hit 读 /metrics 的 allow_hit 槽位（辅助证据，不是必需断言）。
# 任何一步读不到就返回空——指标是旁路，不该左右验收结果。
allow_hit() {
  local out
  command -v curl >/dev/null 2>&1 || return 0
  out=$(curl -fsS --max-time 2 http://127.0.0.1:9601/metrics 2>/dev/null) || return 0
  printf '%s\n' "$out" | sed -n 's/.*slot="allow_hit"} *//p' | head -1
}

allow_hit_or_na() {
  local v
  v=$(allow_hit)
  printf '%s' "${v:-n/a}"
}

# ---------------------------------------------------------------------------
# 监听器：一次性 nc 循环（每个连接一个 nc，-q 1 后再起下一个）
#
# 循环跑在**一个独立的 bash 进程**里（脚本内容写在 $WORK/listener.sh），而不是
# 脚本自己的一个子 shell。理由是崩溃卫生：进程的 argv 会被带进 pgrep -f 的视野，
# 所以循环进程与它起的 nc 子进程都能按标记被下一次运行精确找到并杀掉。
#
# 一开始的写法是 `listener_loop &`（脚本内的子 shell）+ argv[0] 标记的 nc。实测
# 被 SIGKILL 之后会残留一个**看不见的**循环：子 shell 的 argv 就是脚本自己的
# （`bash scripts/e2e.sh`），不带任何标记；杀掉它的 nc 子进程后，循环立刻再起一个，
# 端口继续被占住——下一次运行的"监听器自检"就会假失败（也能让断言整体失真）。
# 现在三个角色都可识别：循环进程（脚本路径 + 标记参数）、它的 nc 子进程（argv[0]）。
# ---------------------------------------------------------------------------
start_listener() {
  cat >"$WORK/listener.sh" <<'LISTENER_EOF'
#!/usr/bin/env bash
# knok M2 e2e 监听器循环（由 scripts/e2e.sh 生成）
# 参数：<受保护端口> <nc 的 argv[0] 标记> <循环标记（仅用于 argv 标识）>
set -uo pipefail
port="$1"; ncmark="$2"
cur=""
trap 'if [ -n "$cur" ]; then kill "$cur" 2>/dev/null || true; fi; exit 0' TERM INT
while :; do
  printf 'knok-e2e-ok\n' | exec -a "$ncmark" nc -l -p "$port" -q 1 >/dev/null 2>&1 &
  cur=$!
  wait "$cur" 2>/dev/null || true
  cur=""
done
LISTENER_EOF
  chmod +x "$WORK/listener.sh"
  "${BASH:-bash}" "$WORK/listener.sh" "$PORT" "$LISTEN_MARK" "$LOOP_MARK" >/dev/null 2>&1 &
  LISTENER_PID=$!
}

# stop_listener：先让监听器进程的 trap 杀掉当前 nc，超时才 KILL。
stop_listener() {
  local pid=$LISTENER_PID i=0
  LISTENER_PID=""
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 30 ]; do
      sleep 0.1
      i=$((i + 1))
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

# kill_marked <signal>：给所有带本次运行标记的进程发信号（干净回收的兜底通道）。
kill_marked() {
  local sig="$1" pids p
  pids=$(pgrep -f -- "$RUN_MARK" 2>/dev/null || true)
  [ -n "$pids" ] || return 0
  for p in $pids; do
    kill "-$sig" "$p" 2>/dev/null || true
  done
}

# port_owner_pid：返回当前监听 $PORT 的进程 PID（没有则空）。
#
# 末尾的 `|| true` 是必需的：脚本开着 pipefail，grep 找不到时返回 1，会让整条
# 管道以 1 结束——赋值语句因此变成失败命令，set -e 会**静默中止整个脚本**
# （实测踩过：清理干净之后恰好就没有持有者，于是收尾核查永远跑不到）。
port_owner_pid() {
  ss -lntp 2>/dev/null | grep -- ":$PORT " |
    sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1 || true
}

# kill_port_owner <signal>：清掉持有 $PORT 的监听进程**以及它的父进程**。
#
# 只认端口归属，不认标记：这样连"旧版本脚本留下的、argv 里没有标记却不断重起
# 子进程的循环"也能收拾掉（实测踩过：只杀 nc 子进程，父循环立刻再起一个）。
# 护栏：绝不碰 PID 1、本脚本自身、本脚本的父 shell——避免误伤。
kill_port_owner() {
  local sig="$1" pid ppid
  pid=$(port_owner_pid)
  [ -n "$pid" ] || return 0
  ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
  for ppid in $ppid; do
    if [ "$ppid" != "1" ] && [ "$ppid" != "$$" ] && [ "$ppid" != "$PPID" ]; then
      kill "-$sig" "$ppid" 2>/dev/null || true
    fi
  done
  kill "-$sig" "$pid" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 守护进程
# ---------------------------------------------------------------------------
# start_daemon <config> <logfile>
start_daemon() {
  local cfg="$1" log="$2"
  : >"$log"
  "$BIN/knokd" -config "$cfg" >"$log" 2>&1 &
  DAEMON_PID=$!
  DAEMON_LOG="$log"
  DAEMON_STARTED=$((DAEMON_STARTED + 1))
}

stop_daemon() {
  local pid=$DAEMON_PID i=0
  DAEMON_PID=""
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 30 ]; do
      sleep 0.1
      i=$((i + 1))
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

# reset_kernel_state <config> <label>：拆表 + 两个后端摘附着 + 删 pin 目录。
# 用于 step 5 之前把上一轮的授权清空（否则"不敲门也打开"可能是上一轮的残留授权
# 造成的假通过）。
reset_kernel_state() {
  local cfg="$1" label="$2"
  if ! "$BIN/knokd" -config "$cfg" -uninstall >>"$WORK/uninstall.log" 2>&1; then
    printf -- '--- uninstall log ---\n'
    tail -n 20 "$WORK/uninstall.log" || true
    die "$label: knokd -uninstall failed (log above)"
  fi
}

# sweep_strays：清掉上一次运行可能泄漏的进程（脚本被 SIGKILL 时 trap 不会执行），
# 并删掉上一次留下的临时目录。两种形态都要扫：
#   * 带本次标记的：knokd（-config 指向 /tmp/knok-e2e.*）、监听器循环进程、
#     监听器起的 nc 子进程
#   * 更早的手工运行泄漏的 `nc -l -p <PORT>`（argv[0] 没有标记）
# 残留的监听器持有 22222，残留的守护进程会让端口处于 drop 状态，两者都会让本次
# 运行的第一步就失真，所以这里必须清掉并报出来。收尾同样复用 kill_marked。
sweep_strays() {
  local found="" d="" left=""
  found=$(pgrep -af -- "$RUN_MARK" 2>/dev/null || true)
  if [ -n "$found" ]; then
    printf 'WARN  startup: cleaning processes left by a previous run:\n%s\n' "$found"
  fi
  found=$(pgrep -af -- "nc -l -p $PORT" 2>/dev/null || true)
  if [ -n "$found" ]; then
    printf 'WARN  startup: cleaning leftover listener(s) on port %s:\n%s\n' "$PORT" "$found"
  fi
  # 两趟 TERM：循环进程被杀掉之前可能正好又起了一个 nc，第二趟收拾它。
  kill_marked TERM
  pkill -f -- "nc -l -p $PORT" 2>/dev/null || true
  kill_port_owner TERM
  sleep 0.3
  kill_marked TERM
  kill_port_owner TERM
  sleep 0.2
  left=$(pgrep -f -- "$RUN_MARK" 2>/dev/null || true)
  if [ -n "$left" ]; then
    printf 'WARN  startup: processes survived SIGTERM, sending SIGKILL: %s\n' "$(pgrep -af -- "$RUN_MARK" | tr '\n' ';')"
    kill_marked KILL
    kill_port_owner KILL
    sleep 0.2
  fi
  for d in /tmp/"$RUN_MARK".*; do
    [ -d "$d" ] || continue
    printf 'WARN  startup: removing leftover temp dir from a previous run: %s\n' "$d"
    rm -rf -- "$d"
  done
  left=$(pgrep -f -- "$RUN_MARK" 2>/dev/null || true)
  if [ -n "$left" ]; then
    die "startup sweep: processes still alive after SIGKILL: $(pgrep -af -- "$RUN_MARK" | tr '\n' ';')"
  fi
  left=$(port_owner_pid)
  if [ -n "$left" ]; then
    printf 'WARN  startup: pid %s still listens on %s: %s\n' "$left" "$PORT" \
      "$(tr '\0' ' ' <"/proc/$left/cmdline" 2>/dev/null || true)"
    kill_port_owner KILL
    sleep 0.2
  fi
  left=$(port_owner_pid)
  if [ -n "$left" ]; then
    die "startup sweep: port $PORT is still held by pid $left after cleanup"
  fi
}

# listener_bound：确认**本脚本自己的** nc 监听器持有 $PORT。
#
# 不能只靠"探测成功"证明监听器可用：端口上若有一个外来进程在听，探测同样成功，
# 而我们的 nc 因 bind 失败起不来——验收会一路"通过"，实际什么都没测到。
# 因此从 ss 取监听进程的 PID，再核对两件事：它的 cmdline 带本次标记，且它是本次
# 监听器循环进程（LISTENER_PID）的子进程——上一次运行残留的监听器带的是同样的
# 标记，只有父子关系能把它区分开。
listener_bound() {
  local pid cmd owners ppid
  owners=$(ss -lntp 2>/dev/null | grep -- ":$PORT " || true)
  pid=$(printf '%s\n' "$owners" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -1)
  if [ -z "$pid" ]; then
    LAST_LISTENER_OWNER="${owners:-<no listener>}"
    return 1
  fi
  LAST_LISTENER_OWNER="$owners"
  cmd=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
  case "$cmd" in
  *"$LISTEN_MARK"*) ;;
  *)
    LAST_LISTENER_OWNER="$owners (owner pid=$pid cmd=$cmd)"
    return 1
    ;;
  esac
  ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
  if [ -z "$LISTENER_PID" ] || [ "$ppid" != "$LISTENER_PID" ]; then
    LAST_LISTENER_OWNER="$owners (owner pid=$pid parent=$ppid, expected loop $LISTENER_PID)"
    return 1
  fi
  return 0
}

wait_for_listener() {
  local budget="$1" deadline
  deadline=$(( $(now_ms) + budget * 1000 ))
  while :; do
    if listener_bound; then
      return 0
    fi
    if [ "$(now_ms)" -ge "$deadline" ]; then
      return 1
    fi
    sleep 0.1
  done
}
LAST_LISTENER_OWNER=""

# ---------------------------------------------------------------------------
# 收尾核查：机器必须回到运行前的样子
# ---------------------------------------------------------------------------
verify_cleanup() {
  local pins_now tc_now
  printf '\n== cleanup verification\n'

  if pgrep -f -- "$RUN_MARK" >/dev/null 2>&1; then
    printf 'FAIL  cleanup: process(es) still alive: %s\n' \
      "$(pgrep -af -- "$RUN_MARK" | tr '\n' ';')"
    CLEAN_FAIL=1
  else
    printf 'PASS  cleanup: no knokd/listener process left\n'
  fi

  if nft list table inet knok >/dev/null 2>&1; then
    printf 'FAIL  cleanup: nft table "inet knok" still exists\n'
    CLEAN_FAIL=1
  else
    printf 'PASS  cleanup: nft table "inet knok" is gone\n'
  fi

  pins_now=$(ls -A /sys/fs/bpf 2>/dev/null | sort | tr '\n' ' ' || true)
  if [ -e "$PIN_DIR" ] || printf '%s' "$pins_now" | grep -q 'knok'; then
    printf 'FAIL  cleanup: knok pins remain (dir=%s, /sys/fs/bpf: %s)\n' \
      "$PIN_DIR" "${pins_now:-<empty>}"
    CLEAN_FAIL=1
  else
    printf 'PASS  cleanup: no knok pins under /sys/fs/bpf (found: %s)\n' \
      "${pins_now:-<empty>}"
  fi

  tc_now=$(tc filter show dev lo ingress 2>&1 || true)
  if [ "$tc_now" != "$PRE_TC" ]; then
    printf 'FAIL  cleanup: tc ingress on lo changed\n  before: %s\n  after:  %s\n' \
      "${PRE_TC:-<empty>}" "${tc_now:-<empty>}"
    CLEAN_FAIL=1
  else
    printf 'PASS  cleanup: tc ingress on lo unchanged (%s)\n' \
      "$([ -n "$tc_now" ] && printf 'non-empty' || printf 'empty')"
  fi

  if [ -n "$WORK" ] && [ -e "$WORK" ]; then
    printf 'FAIL  cleanup: temp dir still present: %s\n' "$WORK"
    CLEAN_FAIL=1
  else
    printf 'PASS  cleanup: temp dir removed\n'
  fi
}

# ---------------------------------------------------------------------------
# cleanup：trap-driven，成功与失败路径共用
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  set +e
  trap - EXIT INT TERM

  printf '\n== cleanup\n'
  stop_listener
  stop_daemon
  # 兜底：监听器循环进程可能已经起了下一个 nc，或（异常路径下）循环本身还在。
  # 带标记的进程一律清掉——它们只可能是本次运行或上一次泄漏的。
  if pgrep -f -- "$RUN_MARK" >/dev/null 2>&1; then
    printf 'cleanup: killing leftover process(es) matching %s\n' "$RUN_MARK"
    kill_marked TERM
    sleep 0.3
    kill_marked TERM
    sleep 0.2
    kill_marked KILL
    sleep 0.2
  fi
  printf 'cleanup: processes stopped\n'

  # 内核状态回收：表 + 两个后端的附着 + pin 目录。配置还在磁盘上，所以 pin.dir
  # 能被精确定位（-uninstall 的退出码非零 = 回收不完整，这里报出来）。
  local unlog=/dev/null
  [ -n "$WORK" ] && unlog="$WORK/uninstall.log"
  if [ -n "$BIN" ] && [ -x "$BIN/knokd" ] && [ -n "$CFG_SIMPLE" ] && [ -f "$CFG_SIMPLE" ]; then
    if "$BIN/knokd" -config "$CFG_SIMPLE" -uninstall >>"$unlog" 2>&1; then
      printf 'cleanup: knokd -uninstall ok (table, attachments, pins removed)\n'
    else
      printf 'cleanup: WARN knokd -uninstall returned non-zero (kernel state may remain)\n'
      [ -f "$unlog" ] && tail -n 20 "$unlog" || true
    fi
  fi

  # 临时文件与 pin 目录（pin 目录正常已由 -uninstall 删掉，这里兜底）
  if [ -n "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
  if [ -e "$PIN_DIR" ]; then
    rm -rf -- "$PIN_DIR"
  fi

  verify_cleanup

  printf '\n================ M2 e2e summary ================\n'
  if [ "${#RESULTS[@]}" -gt 0 ]; then
    printf '%s\n' "${RESULTS[@]}"
  fi
  printf 'cleanup: %s\n' "$([ "$CLEAN_FAIL" -eq 0 ] && printf 'clean' || printf 'NOT clean')"
  if [ "$rc" -eq 0 ] && [ "$FAILED" -eq 0 ] && [ "$CLEAN_FAIL" -eq 0 ]; then
    printf 'E2E PASS\n'
    exit 0
  fi
  printf 'E2E FAIL (exit %s)\n' "$rc"
  [ "$rc" -ne 0 ] && exit "$rc"
  exit 1
}

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
  printf 'e2e: Linux only (this host is %s)\n' "$(uname -s)" >&2
  exit 1
fi
if [ "$(id -u)" != 0 ]; then
  printf 'e2e: must run as root — use "sudo make e2e"\n' >&2
  exit 1
fi
for tool in go nc nft tc ss pgrep pkill; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'e2e: required tool not found: %s\n' "$tool" >&2
    exit 1
  fi
done

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$REPO_ROOT"
printf 'e2e: repo %s\n' "$REPO_ROOT"

# 运行前的快照（收尾时逐项对比）
PRE_TC=$(tc filter show dev lo ingress 2>&1 || true)
PRE_PINS=$(ls -A /sys/fs/bpf 2>/dev/null | sort | tr '\n' ' ' || true)
printf 'e2e: pre-run tc ingress on lo: %s\n' "$([ -n "$PRE_TC" ] && printf 'non-empty' || printf 'empty')"
printf 'e2e: pre-run /sys/fs/bpf: %s\n' "${PRE_PINS:-<empty>}"
if nft list table inet knok >/dev/null 2>&1; then
  printf 'WARN  startup: leftover nft table "inet knok" found (a previous run did not clean up); the pre-flight reset below removes it\n'
fi
# trap 从这一刻起生效：此前（前置检查、快照）失败都还没有任何东西需要回收，
# 因此不必打出收尾段落。此后创建的进程/内核状态都由 cleanup 负责。
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# 任何"意外中止"（set -e 触发的失败，例如忘了 `|| true` 的三段管道）都要留下
# 位置与命令，否则只有一个空的汇总表，排查得从零开始。ERR trap 的触发条件与
# errexit 一致：if/while/&&/|| 里的命令失败不会误报。
trap 'printf "ERROR e2e: aborted at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
sweep_strays

WORK=$(mktemp -d "/tmp/$RUN_MARK.XXXXXX")
BIN="$WORK/bin"
CFG_SIMPLE="$WORK/knokd.toml"
CFG_ADMIN="$WORK/knokd-admin.toml"
mkdir -p "$BIN"

printf '\n== build\n'
go build -o "$BIN/knokd" ./cmd/knokd
go build -o "$BIN/knok" ./cmd/knok
printf 'built %s\n' "$("$BIN/knok" version)"

if ! PSK=$("$BIN/knok" keygen --psk); then
  die "keygen --psk failed"
fi
if ! printf '%s' "$PSK" | grep -Eq '^hex:[0-9a-f]{64}$'; then
  printf 'e2e: keygen --psk produced an unexpected value: %s\n' "$PSK" >&2
  exit 1
fi
printf 'generated a fresh pre-shared key for this run (%s…)\n' "${PSK:0:12}"

# 配置：唯一配置来源是文件（CLI 只有 -config/-uninstall/-metrics）。
# max_ttl = 1m 覆盖 step 4 的 60s；admin_allow 只在第二份配置里出现。
write_config() {
  local path="$1" admin="$2"
  cat >"$path" <<EOF
# knok M2 e2e (generated by scripts/e2e.sh; path marker: $RUN_MARK)
[keys]
psk = "$PSK"

[listen]
spa_udp_port = $SPA_PORT
protected_ports = [$PORT]

[policy]
allowed_ports = [$PORT]
max_ttl = "1m"
ts_window = "300s"

[safety]
admin_allow = [$admin]

[interfaces]
mode = "explicit"
explicit = ["lo"]

[pin]
dir = "$PIN_DIR"
EOF
}
write_config "$CFG_SIMPLE" ""
write_config "$CFG_ADMIN" '"127.0.0.1/32"'

# 起始状态必须干净：上一次运行被 SIGKILL 掉、或有人手工调过 knokd，都可能留下
# inet knok 表与 /sys/fs/bpf 下的 pin。这里显式回收一次，让 step 1 的"基线"是
# 真的基线（残留的 pin 会让上一次的授权继续生效，断言就失去了意义）。
printf '\n== pre-flight reset (remove any leftover knok kernel state)\n'
reset_kernel_state "$CFG_SIMPLE" "pre-flight reset"
if nft list table inet knok >/dev/null 2>&1 || [ -e "$PIN_DIR" ]; then
  die "pre-flight reset: knok kernel state still present after -uninstall"
fi
printf 'pre-flight reset: no table, no pins — baseline is clean\n'

# ---------------------------------------------------------------------------
# step 0：监听器自检（没有防火墙时探测必须成功）
# 这一步让后面的"timeout"具备意义：监听器确实在听，timeout 只可能来自 drop 规则。
# ---------------------------------------------------------------------------
step "0/5 listener sanity: probe must succeed with no firewall in place"
start_listener
if ! wait_for_listener "$OPEN_BUDGET"; then
  printf 'ss: %s\n' "${LAST_LISTENER_OWNER:-<empty>}"
  die "no listener owned by this script on port $PORT within ${OPEN_BUDGET}s (a foreign process may hold the port)"
fi
if ! wait_for_state open "$OPEN_BUDGET" "listener up (no drop rule yet)"; then
  die "listener never became reachable on 127.0.0.1:$PORT (last observed: $LAST_PROBE)"
fi
pass "step 0: listener reachable on 127.0.0.1:$PORT before any firewall ($LAST_PROBE)"

# ---------------------------------------------------------------------------
# step 1：基线——装上 drop 规则后必须静默丢弃
# ---------------------------------------------------------------------------
step "1/5 baseline: protected port must be silently dropped before any knock"
start_daemon "$CFG_SIMPLE" "$WORK/daemon-1.log"
if ! wait_for_log "$DAEMON_LOG" 'firewall installed' 10; then
  die "daemon 1 never logged 'firewall installed' (last observed probe: $(probe))"
fi
if ! wait_for_state timeout "$OPEN_BUDGET" "silent drop before knock"; then
  die "port not silently dropped before the knock (last observed: $LAST_PROBE)"
fi
HIT_BASE=$(allow_hit)
METRICS_OK=0
[ -n "$HIT_BASE" ] && METRICS_OK=1
pass "step 1: port $PORT silently dropped (probe=timeout) with the drop rule installed (allow_hit=${HIT_BASE:-n/a})"

# ---------------------------------------------------------------------------
# step 2：敲门后端口必须打开
# ---------------------------------------------------------------------------
step "2/5 knock: ./knok auth --ports $PORT must open it"
if ! KNOCK_OUT=$("$BIN/knok" auth --server "$DST" --spa-port "$SPA_PORT" \
  --ports "$PORT" --ttl "${TTL}s" --psk "$PSK" 2>&1); then
  printf '%s\n' "$KNOCK_OUT"
  die "knok auth failed to send the knock"
fi
printf 'knok auth: %s\n' "$KNOCK_OUT"
if ! wait_for_state open "$OPEN_BUDGET" "port open after knock"; then
  die "port $PORT did not open within ${OPEN_BUDGET}s after the knock (last observed: $LAST_PROBE)"
fi
HIT_AFTER=$(allow_hit)
if [ "$METRICS_OK" -eq 1 ] && [ -n "$HIT_AFTER" ] && [ "$HIT_AFTER" -le "${HIT_BASE:-0}" ]; then
  die "allow_hit did not increase after the knock ($HIT_BASE -> ${HIT_AFTER:-n/a})"
fi
pass "step 2: order opened the port (probe=open, allow_hit ${HIT_BASE:-n/a} -> ${HIT_AFTER:-n/a})"

# ---------------------------------------------------------------------------
# step 3：TTL 到期后必须重新关闭（静默丢弃，不是 RST）
# ---------------------------------------------------------------------------
step "3/5 TTL: port must close again after the ${TTL}s grant expires"
if ! wait_for_state timeout $((TTL + OPEN_BUDGET)) "silent drop after TTL expiry"; then
  die "port $PORT was still reachable after the ${TTL}s TTL expired (last observed: $LAST_PROBE)"
fi
pass "step 3: grant expired after ~${TTL}s and the port is silently dropped again (probe=timeout)"

# ---------------------------------------------------------------------------
# step 4：重启存活——授权由 pinned map + pinned TCX link 承载，守护进程死了也在
# ---------------------------------------------------------------------------
step "4/5 restart survival: the grant must outlive the daemon"
if ! KNOCK_OUT=$("$BIN/knok" auth --server "$DST" --spa-port "$SPA_PORT" \
  --ports "$PORT" --ttl "${LONG_TTL}s" --psk "$PSK" 2>&1); then
  printf '%s\n' "$KNOCK_OUT"
  die "knok auth failed to send the second knock"
fi
if ! wait_for_state open "$OPEN_BUDGET" "port open after second knock"; then
  die "port $PORT did not open after the second knock (last observed: $LAST_PROBE)"
fi
HIT_BEFORE_RESTART=$(allow_hit)
printf 'stopping daemon (pid %s) — the drop rule and the grant must stay in the kernel\n' "$DAEMON_PID"
stop_daemon
if ! wait_for_state open "$OPEN_BUDGET" "port open with the daemon stopped"; then
  die "grant lost when the daemon stopped (pinned link/map should keep it; last observed: $LAST_PROBE)"
fi
printf 'grant survives with no daemon running (probe=open)\n'
start_daemon "$CFG_SIMPLE" "$WORK/daemon-2.log"
if ! wait_for_log "$DAEMON_LOG" 'firewall installed' 10; then
  die "restarted daemon never logged 'firewall installed'"
fi
if ! wait_for_state open "$OPEN_BUDGET" "port open after daemon restart"; then
  die "grant lost across the daemon restart (last observed: $LAST_PROBE)"
fi
HIT_AFTER_RESTART=$(allow_hit)
pass "step 4: grant survived the daemon restart (probe=open, allow_hit ${HIT_BEFORE_RESTART:-n/a} -> ${HIT_AFTER_RESTART:-n/a})"

# ---------------------------------------------------------------------------
# step 5：逃生通道 safety.admin_allow——不敲门也打开，且未被覆盖的源仍被 drop
# 先把上一轮的授权清干净（-uninstall 删掉 pinned map），否则"打开"可能是残留授权。
# ---------------------------------------------------------------------------
step "5/5 admin_allow escape hatch: no knock, but the drop rule still applies to others"
stop_daemon
reset_kernel_state "$CFG_SIMPLE" "step 5 reset"
if nft list table inet knok >/dev/null 2>&1; then
  die "step 5 reset: nft table inet knok still present after -uninstall"
fi
if [ -e "$PIN_DIR" ]; then
  die "step 5 reset: pin dir $PIN_DIR still present after -uninstall"
fi
printf 'kernel state reset: no table, no pins, no grants — starting daemon 3 with admin_allow\n'
start_daemon "$CFG_ADMIN" "$WORK/daemon-3.log"
if ! wait_for_log "$DAEMON_LOG" 'firewall installed' 10; then
  die "daemon 3 (admin_allow) never logged 'firewall installed'"
fi
if ! grep -q '"msg":"admin_allow granted forever"' "$DAEMON_LOG"; then
  die "daemon 3 did not log the admin_allow grant"
fi
if ! grep -q "\"addr\":\"$DST\".*\"port\":$PORT" "$DAEMON_LOG"; then
  sed -n '/admin_allow/p' "$DAEMON_LOG" || true
  die "daemon 3 did not log the admin_allow grant for $DST:$PORT"
fi
if ! wait_for_state open "$OPEN_BUDGET" "admin_allow opens the port without a knock"; then
  die "admin_allow did not open $PORT for $DST without a knock (last observed: $LAST_PROBE)"
fi
# 反证：同一端口对未被 admin_allow 覆盖的源地址仍然是静默丢弃——这同时证明了
# drop 规则确实装在链上（否则它会直接连上监听器）。
if ! wait_for_state timeout "$OPEN_BUDGET" "other sources still dropped" "$FOREIGN_SRC"; then
  die "source $FOREIGN_SRC reached $PORT: the drop rule is missing (last observed: $LAST_PROBE)"
fi
pass "step 5: admin_allow opened $PORT for $DST with no knock, while $FOREIGN_SRC stays dropped"

printf '\nall steps done; running cleanup\n'