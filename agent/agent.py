"""
원격 PC 연결 관리(PCmoa) — 연결 프로그램(에이전트) v1.4 (각 PC에서 실행, Windows/Linux 공통)

그냥 실행:  python agent.py            → 메인 PC 주소와 6자리 연결 코드를 물어본 뒤 등록·연결
한 줄로:    python agent.py --server http://192.168.0.10:8000 --code 123456
자동 시작:  python agent.py --install  → 로그인 시 자동 실행 등록 (Windows 작업 스케줄러 / Linux systemd --user)
이후:       python agent.py            → agent.json의 PC별 토큰으로 바로 연결
옵션:       --enroll <등록 토큰>  관리자용 일괄 등록   --dry-run  종료/재부팅을 실제로 실행하지 않음
            --allow-sleep  연결 중에도 절전 허용 (기본은 연결 프로그램이 켜져 있는 동안 절전 막기)
삭제:       python agent.py --uninstall  → 자동 시작 해제 + 실행 중인 연결 프로그램 종료 + 등록 정보 삭제
"""
import os
import sys

# ----------------------------------------------------------------- 지킴이(가벼운 시작): 무거운 모듈을 불러오기 전에 갈라진다
# 지킴이는 자식(실제 연결 프로그램)을 띄우고 지켜보기만 하므로, 네트워크·화면 모듈을 불러올 필요가 없다 → 메모리 절약
if __name__ == "__main__" and not os.environ.get("PCM_CHILD") and \
        not any(x in sys.argv for x in ("--register", "--install-admin", "--uninstall", "-h", "--help")):
    import subprocess
    import time
    from pathlib import Path as _P
    _HERE = _P(sys.executable).resolve().parent if getattr(sys, "frozen", False) else _P(__file__).resolve().parent
    _ALIVE, _LOG = _HERE / "agent.alive", _HERE / "agent.log"
    _HANG = int(os.environ.get("PCM_HANG_SECONDS", "120"))
    if os.name == "nt":   # 콘솔 '빠른 편집' 끄기 — 창을 클릭해도 멈추지 않게
        try:
            import ctypes
            _k = ctypes.windll.kernel32
            _h = _k.GetStdHandle(-10)
            _m = ctypes.c_uint32()
            if _k.GetConsoleMode(_h, ctypes.byref(_m)):
                _k.SetConsoleMode(_h, (_m.value | 0x0080) & ~0x0040)
        except Exception:
            pass

    def _log(text: str) -> None:
        try:
            if _LOG.exists() and _LOG.stat().st_size > 1_000_000:
                _LOG.replace(_LOG.with_suffix(".log.old"))
            with open(_LOG, "a", encoding="utf-8") as f:
                f.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')}\n{text}\n")
        except Exception:
            pass

    def _supervise() -> None:
        """연결 프로그램을 자식으로 돌리고, 오류로 꺼지거나 2분 넘게 멈추면 다시 띄운다.
        종료 코드: 0 정상 · 2 다시 등록 필요 · 3 업데이트됨(바로 재시작) · 4 이미 실행 중"""
        args = ([sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(_P(__file__).resolve())]) + sys.argv[1:]
        env = dict(os.environ, PCM_CHILD="1")
        fails = 0
        while True:
            t0, hung = time.time(), False
            try:
                _ALIVE.touch()
                child = subprocess.Popen(args, env=env)
                while True:
                    try:
                        rc = child.wait(timeout=5)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        idle = time.time() - _ALIVE.stat().st_mtime
                    except OSError:
                        idle = 0
                    if idle > _HANG:
                        hung = True
                        child.kill()
                        rc = child.wait()
                        break
            except KeyboardInterrupt:
                return
            env.pop("PCM_LAST_CRASH", None)
            if rc in (0, 2, 4):
                if rc == 2 and sys.stdin and sys.stdin.isatty():
                    input("Enter를 누르면 닫힙니다")
                return
            if rc == 3:
                continue
            if rc in (3221225786, -2, 130):          # Ctrl+C로 끈 경우
                return
            fails = fails + 1 if time.time() - t0 < 60 else 1
            wait = 1 if hung else min(60, 3 * fails)
            msg = (f"연결 프로그램이 {_HANG}초 넘게 응답이 없어 다시 시작합니다" if hung
                   else f"연결 프로그램이 오류로 멈췄습니다 (종료 코드 {rc}) — {wait}초 뒤 다시 시작합니다")
            print(f"[agent] {msg}. 자세한 오류: {_LOG}", file=sys.stderr, flush=True)
            _log(msg)
            env["PCM_LAST_CRASH"] = ("응답 없음(멈춤) → 강제 재시작" if hung else f"종료 코드 {rc}") + f", {int(time.time() - t0)}초 동안 실행됨"
            time.sleep(wait)

    _supervise()
    sys.exit(0)

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import io
# 무거운 모듈(psutil, mss, pillow)은 실제로 쓸 때 불러온다 — 지킴이 프로세스와 유휴 상태 메모리를 줄이려고
psutil = None
mss = Image = None
SHOT_OK = False

HERE = Path(__file__).resolve().parent
STATE = HERE / "agent.json"
INBOX = Path.home() / "pcmanager" / "inbox"   # 받은 파일은 여기에만 저장한다
WIN = platform.system() == "Windows"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 시스템 프록시 무시


ALIVE = HERE / "agent.alive"      # 지킴이가 보는 '살아 있음' 표시 (몇 초마다 수정 시각만 바꾼다)
_last_alive = 0.0


def alive() -> None:
    global _last_alive
    if time.time() - _last_alive < 3 or not os.environ.get("PCM_CHILD"):
        return
    _last_alive = time.time()
    try:
        ALIVE.touch()
    except OSError:
        pass


def _nonblocking_print() -> None:
    """창(콘솔)이 멈춰도 연결 프로그램이 같이 멈추지 않도록, 화면 출력은 따로 도는 쓰레드가 맡는다"""
    import builtins
    import queue as _q
    q: "_q.Queue" = _q.Queue(maxsize=1000)
    real = builtins.print

    def writer() -> None:
        while True:
            args, kw = q.get()
            try:
                real(*args, **kw)
            except Exception:
                pass

    threading.Thread(target=writer, daemon=True).start()

    def nb_print(*args, **kw) -> None:
        try:
            q.put_nowait((args, kw))
        except _q.Full:          # 창이 오래 멈춰 있으면 출력은 버린다 (연결이 우선)
            pass
    builtins.print = nb_print


def call(url: str, data: dict | None = None, token: str = "", timeout: int = 10) -> dict:
    req = urllib.request.Request(url, method="POST" if data is not None else "GET",
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", "X-Agent-Token": token})
    with OPENER.open(req, timeout=timeout) as r:
        return json.loads(r.read())


def local_ip(server_host: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((server_host, 9))
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


def local_mac() -> str:
    n = uuid.getnode()
    return ":".join(f"{(n >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))


# ---- GPU 사용률: NVIDIA는 nvidia-smi, 그 밖의 Windows GPU(Intel·AMD)는 성능 카운터. 10초마다 뒤에서 갱신
GPU: dict = {}


def _gpu_nvidia() -> dict:
    exe = shutil.which("nvidia-smi") or (r"C:\Windows\System32\nvidia-smi.exe" if WIN and os.path.exists(r"C:\Windows\System32\nvidia-smi.exe") else None)
    if not exe:
        return {}
    r = subprocess.run([exe, "--query-gpu=name,utilization.gpu,memory.used,memory.total", "--format=csv,noheader,nounits"],
                       capture_output=True, timeout=8, creationflags=0x08000000 if WIN else 0)
    rows = [x.split(", ") for x in r.stdout.decode(errors="ignore").strip().splitlines() if x.strip()]
    if r.returncode or not rows:
        return {}
    name, util, used, total = rows[0][:4]   # 여러 장이면 첫 번째 GPU
    return {"gpu": float(util), "gpu_name": name.strip(), "vram_used": float(used) / 1024, "vram_total": float(total) / 1024}


# 작업 관리자와 같은 계산: 엔진마다 모든 프로세스 사용률을 더하고, 그중 가장 바쁜 엔진 값을 GPU 사용률로 본다.
# 성능 카운터 이름은 한국어 Windows에서 번역돼 있어서, 번역되지 않는 WMI 클래스 이름으로 읽는다.
PS_GPU = (r"$e=Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction SilentlyContinue;"
          r"$u=($e | Group-Object { $_.Name -replace '^pid_\d+_','' } |"
          r" ForEach-Object { ($_.Group | Measure-Object UtilizationPercentage -Sum).Sum } | Measure-Object -Maximum).Maximum;"
          r"$n=(Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Basic|Remote|Virtual' } | Select-Object -First 1).Name;"
          r"Write-Output ('{0}|{1}' -f [math]::Round([double]$u,1), $n)")


def _gpu_windows() -> dict:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_GPU],
                       capture_output=True, timeout=20, creationflags=0x08000000)
    line = r.stdout.decode("utf-8", errors="ignore").strip().splitlines()
    if not line or "|" not in line[-1]:
        return {}
    util, name = line[-1].split("|", 1)
    try:
        return {"gpu": min(100.0, float(util or 0)), "gpu_name": name.strip()}
    except ValueError:
        return {}


WATCHED = [True]   # 대시보드를 누가 보고 있는지 (heartbeat 응답으로 갱신)


def _gpu_loop() -> None:
    while True:
        if WATCHED[0]:     # 아무도 안 볼 때는 GPU를 읽지 않는다 (Windows는 매번 PowerShell을 띄워 비용이 큼)
            try:
                g = _gpu_nvidia() or (_gpu_windows() if WIN else {})
                GPU.clear(); GPU.update(g)
            except Exception:
                GPU.clear()
        time.sleep(10)


def metrics() -> dict:
    if not GPU and not getattr(metrics, "started", False):
        metrics.started = True
        threading.Thread(target=_gpu_loop, daemon=True).start()
    global psutil
    if psutil is None:
        try:
            import psutil as _p
            psutil = _p
        except ImportError:
            psutil = False
    out = {"cpu": 0, "mem": 0, "uptime": 0}
    if psutil:
        vm = psutil.virtual_memory()
        out = {"cpu": psutil.cpu_percent(interval=None), "mem": vm.percent, "uptime": int(time.time() - psutil.boot_time()),
               "ram_used": round((vm.total - vm.available) / 2**30, 1), "ram_total": round(vm.total / 2**30, 1)}
    return {**out, **GPU}


def run_shell(cmd: str, timeout: int = 60) -> tuple[int, str]:
    """Windows는 PowerShell, Linux는 bash로 실행하고 출력(앞뒤 20KB)을 돌려준다"""
    args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd] if WIN else ["bash", "-lc", cmd]
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, cwd=str(INBOX))
        raw = p.stdout + p.stderr
        try:      # Windows도 "UTF-8 전역 언어 지원"이 켜진 PC는 UTF-8로 나온다 — UTF-8 먼저, 안 되면 CP949
            out = raw.decode("utf-8")
        except UnicodeDecodeError:
            out = raw.decode("cp949" if WIN else "utf-8", errors="replace")
        return p.returncode, out[-20000:]
    except subprocess.TimeoutExpired:
        return 124, f"{timeout}초 안에 끝나지 않아 중단했습니다"
    except Exception as e:
        return 1, str(e)


def download(server: str, token: str, job: dict) -> tuple[int, str]:
    INBOX.mkdir(parents=True, exist_ok=True)
    dest = INBOX / Path(job["name"]).name          # 경로 조작 방지: 파일명만 사용
    req = urllib.request.Request(f"{server}/agent/files/{job['payload']}", headers={"X-Agent-Token": token})
    h = hashlib.sha256()
    with OPENER.open(req, timeout=120) as r, open(dest, "wb") as f:
        while chunk := r.read(1024 * 1024):
            h.update(chunk)
            f.write(chunk)
            alive()
    if h.hexdigest() != job.get("sha256"):
        dest.unlink(missing_ok=True)
        return 1, "전송 후 해시가 달라 파일을 버렸습니다"
    return 0, f"저장: {dest} ({dest.stat().st_size} bytes, sha256 일치)"


# ----------------------------------------------------------------- 브라우저 터미널 (상주 셸)
import threading
import queue


def _git_bash() -> str:
    """Git for Windows의 bash 경로 (WSL의 System32\bash.exe는 제외)"""
    for c in (os.path.expandvars(r"%ProgramFiles%\Git\bin\bash.exe"), os.path.expandvars(r"%ProgramFiles(x86)%\Git\bin\bash.exe"),
              os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\bin\bash.exe")):
        if os.path.exists(c):
            return c
    w = shutil.which("bash") or ""
    return w if w and "system32" not in w.lower() else ""


def _wsl_distros() -> list:
    """설치된 WSL 배포판 이름 — 목록만 읽어 WSL을 켜지는 않는다"""
    exe = shutil.which("wsl") or (r"C:\Windows\System32\wsl.exe" if os.path.exists(r"C:\Windows\System32\wsl.exe") else "")
    if not exe:
        return []
    try:
        r = subprocess.run([exe, "-l", "-q"], capture_output=True, timeout=8, creationflags=0x08000000)
    except Exception:
        return []
    if r.returncode != 0:
        return []
    txt = r.stdout.decode("utf-16-le", "ignore") if b"\x00" in r.stdout else r.stdout.decode("utf-8", "ignore")
    return [x.strip().strip("\x00") for x in txt.splitlines() if x.strip().strip("\x00")]


SHELLS: list = []   # 이 PC에서 쓸 수 있는 셸 — heartbeat로 서버에 알려 터미널 창에서 고르게 한다


def detect_shells() -> list:
    out = []
    if WIN:
        out += [{"id": "powershell", "name": "PowerShell"}, {"id": "cmd", "name": "명령 프롬프트(CMD)"}]
        for d in _wsl_distros():
            out.append({"id": "wsl:" + d, "name": f"Linux (WSL · {d})"})
        if _git_bash():
            out.append({"id": "gitbash", "name": "Git Bash"})
    else:
        for sh, name in (("bash", "bash"), ("zsh", "zsh"), ("sh", "sh")):
            if shutil.which(sh):
                out.append({"id": sh, "name": name})
    return out


class Shell:
    """고른 셸을 파이프로 띄워 두고 입출력을 중계한다 (PTY는 아니라 vim 같은 전체 화면 프로그램은 제한).
    kind: powershell · cmd · wsl:<배포판> · gitbash · bash · zsh · sh"""

    def __init__(self, kind: str = "") -> None:
        kind = kind or ("powershell" if WIN else "bash")
        self.kind = kind
        self.unix = not (kind in ("powershell", "cmd"))
        cwd = str(INBOX)
        flags = 0x08000000 if WIN else 0          # 창 없이
        if kind == "powershell":
            args = ["powershell", "-NoLogo", "-NoProfile", "-Command", "-"]
        elif kind == "cmd":
            args = ["cmd", "/Q", "/D"]
        elif kind.startswith("wsl:"):
            args = ["wsl.exe", "-d", kind[4:], "--cd", "~", "-e", "bash", "--norc"]
        elif kind == "gitbash":
            args = [_git_bash() or "bash", "--norc"]
            cwd = str(Path.home())
        else:
            args = [shutil.which(kind) or kind] + (["--norc"] if kind == "bash" else ["-f"] if kind == "zsh" else [])
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  cwd=cwd, bufsize=0, creationflags=flags)
        self.out: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=self._reader, daemon=True).start()
        if kind == "powershell":
            self.write('[Console]::OutputEncoding=[Text.Encoding]::UTF8; Write-Host ("PS " + (Get-Location).Path + "> ") -NoNewline\n')
        elif kind == "cmd":
            self.write("chcp 65001 >nul\n" + self.prompt_cmd(first=True))
        else:
            self.write(("export TERM=dumb LANG=${LANG:-C.UTF-8}; " if self.unix else "") + self.prompt_cmd(first=True))

    def prompt_cmd(self, first: bool = False) -> str:
        if self.kind == "powershell":
            return 'Write-Host ""; Write-Host ("PS " + (Get-Location).Path + "> ") -NoNewline\n'
        if self.kind == "cmd":
            return ("" if first else "echo.\n") + "<nul set /p =%CD%^>\n"
        nl = "" if first else "\\n"
        return f"printf '{nl}%s@%s:%s$ ' \"$(whoami)\" \"$(hostname -s 2>/dev/null || hostname)\" \"$(pwd | sed \"s#^$HOME#~#\")\"\n"

    def completion_cmd(self, line: str) -> str:
        """현재 입력 줄에 대한 자동완성 후보를 셸에서 뽑는 명령 (마커 사이에 한 줄씩 출력)"""
        if self.kind == "powershell":
            q = line.replace("'", "''")
            return (f"echo {C_START}; (TabExpansion2 '{q}' {len(line)}).CompletionMatches | "
                    f"Select-Object -First 60 | ForEach-Object {{ $_.CompletionText }}; echo {C_END}\n")
        tok = "" if (not line or line.endswith(" ")) else line.split()[-1]
        if self.kind == "cmd":
            q = tok.replace('"', "")
            return f'echo {C_START}& dir /b "{q}*" 2>nul& echo {C_END}\n'
        first = len(line.split()) <= 1 and not line.endswith(" ")
        q = tok.replace("'", "'\\''")
        gen = (f"compgen -c -- '{q}'" if first else
               f"compgen -f -- '{q}' | while read f; do [ -d \"$f\" ] && echo \"$f/\" || echo \"$f\"; done")
        if self.kind in ("zsh", "sh"):   # compgen은 bash 전용 — 파일 이름만
            gen = f"ls -1dp '{q}'* 2>/dev/null"
        return f"echo {C_START}; {gen} | head -60; echo {C_END}\n"

    def _reader(self) -> None:
        import codecs
        # 블록 단위로 읽고, 글자가 블록 경계에서 잘려도 이어 붙여 해석한다 (한글이 깨지지 않게)
        dec = codecs.getincrementaldecoder("utf-8")()
        fd = self.p.stdout.fileno()
        while True:
            try:
                b = os.read(fd, 4096)
            except OSError:
                break
            if not b:
                break
            try:
                txt = dec.decode(b)
            except UnicodeDecodeError:   # PowerShell 버전에 따라 CP949로 나오기도 한다 — 그때부터 CP949로
                dec = codecs.getincrementaldecoder("cp949" if WIN else "utf-8")(errors="replace")
                txt = dec.decode(b)
            if not txt:
                continue
            if self.out.qsize() > 2000:   # 안 읽히면 오래된 출력부터 버린다
                try:
                    self.out.get_nowait()
                except Exception:
                    pass
            self.out.put(txt.replace("\n", "\r\n"))

    def write(self, text: str) -> None:
        if self.p.poll() is None:
            self.p.stdin.write(text.encode("utf-8"))
            self.p.stdin.flush()

    def drain(self) -> str:
        parts = []
        while not self.out.empty():
            parts.append(self.out.get_nowait())
        return "".join(parts)

    def close(self) -> None:
        try:
            self.p.kill()
        except Exception:
            pass


C_START, C_END = "__PCM_C_START__", "__PCM_C_END__"


def term_loop(server: str, token: str, seconds: float = 4.5) -> None:
    """터미널이 열려 있는 동안 0.15초마다 입출력 교환. heartbeat 주기마다 돌아간다."""
    global SHELL, SHELL_KIND
    if SHELL is None or SHELL.p.poll() is not None or SHELL.kind != (SHELL_KIND or SHELL.kind):
        if SHELL is not None:
            SHELL.close()
        SHELL = Shell(SHELL_KIND)
        time.sleep(0.3)
    end = time.time() + seconds
    line = ""        # 브라우저는 키 단위로 보내므로 줄 단위로 모아 셸에 넣는다 (로컬 에코는 브라우저가 함)
    cbuf = None      # 자동완성 출력을 모으는 버퍼 (마커 사이)
    while time.time() < end:
        alive()
        out = SHELL.drain()
        if cbuf is not None:                      # 자동완성 결과 수집 중: 마커 사이만 떼어내 브라우저로 JSON 전송
            cbuf += out
            if C_END in cbuf:
                body, rest = cbuf.split(C_END, 1)
                matches = list(dict.fromkeys(m.strip() for m in body.split(C_START, 1)[-1].splitlines() if m.strip()))
                out = "\x00C" + json.dumps({"matches": matches}, ensure_ascii=False) + rest.lstrip("\r\n")
                cbuf = None
            else:
                out = ""
        try:
            res = call(f"{server}/agent/term", {"output": out}, token, timeout=5)
        except Exception as e:
            print(f"[agent] 터미널 중계 실패: {e}", file=sys.stderr)
            return
        if not res.get("active"):
            return
        want = res.get("shell") or ""
        if want and want != SHELL.kind:          # 터미널 창에서 셸을 바꿈 → 새 셸로 다시 연다
            SHELL_KIND = want
            SHELL.close()
            try:
                SHELL = Shell(want)
            except Exception as e:
                SHELL = Shell()
                out_err = f"\r\n[터미널] '{want}' 셸을 열 수 없어 기본 셸로 엽니다: {e}\r\n"
                call(f"{server}/agent/term", {"output": out_err}, token, timeout=5)
            line = ""
            continue
        for chunk in res.get("input", []):
            if chunk.startswith("\x00C"):          # Tab: 자동완성 요청 (뒤에 현재 줄)
                cbuf = ""
                SHELL.write(SHELL.completion_cmd(chunk[2:]))
                continue
            for chv in chunk:
                if chv in ("\r", "\n"):
                    SHELL.write(line + "\n" + SHELL.prompt_cmd())   # 명령 뒤 빈 줄 + 프롬프트
                    line = ""
                elif chv == "\x7f":
                    line = line[:-1]
                elif chv == "\x03":                  # Ctrl+C: 현재 줄 버리고 셸 재시작
                    line = ""
                    SHELL.close(); SHELL = Shell(SHELL.kind)
                elif chv >= " ":
                    line += chv
        time.sleep(0.15)


SHELL = None
SHELL_KIND = ""


def _load_shot() -> bool:
    global SHOT_OK, mss, Image
    try:
        import mss as _mss
        from PIL import Image as _Image
        mss, Image, SHOT_OK = _mss, _Image, True
    except Exception:
        SHOT_OK = False
    return SHOT_OK


def ensure_shot_modules() -> bool:
    """캡처 모듈을 불러오고, 없으면 그 자리에서 pip로 설치를 한 번 시도한다 (재시작 불필요)"""
    global SHOT_OK, mss, Image
    if SHOT_OK or _load_shot():
        return True
    print("[agent] 화면 캡처 모듈 설치 중 (mss, pillow)...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--user", "mss", "pillow"], capture_output=True, timeout=180)
    try:
        import importlib, site
        importlib.invalidate_caches()
        if site.getusersitepackages() not in sys.path:
            sys.path.append(site.getusersitepackages())
        import mss as _mss
        from PIL import Image as _Image
        mss, Image, SHOT_OK = _mss, _Image, True
    except Exception:
        SHOT_OK = False
    return SHOT_OK


def screenshot(server: str, token: str, cmd_id: int) -> tuple[int, str]:
    """주 모니터를 JPEG 한 장으로 캡처해 서버에 올린다 (명령 결과 확인용, 단발)"""
    try:
        g = get_grabber()
    except Exception as e:
        return 1, f"화면 캡처 불가: {e}"
    try:
        jpg, w, h, _, _ = g.grab(max_w=1600, quality=70)
        req = urllib.request.Request(f"{server}/agent/shot/{cmd_id}", data=jpg, method="POST",
                                     headers={"Content-Type": "image/jpeg", "X-Agent-Token": token})
        with OPENER.open(req, timeout=30):
            pass
        return 0, f"화면 캡처 저장 ({w}x{h})"
    except Exception as e:
        return 1, f"캡처 실패: {e}"
    finally:
        g.close()


# ----------------------------------------------------------------- 화면 보기·조종 (v1.4)
# Windows: 추가 모듈 없이 동작 — 캡처는 PowerShell(.NET System.Drawing) 상주 프로세스, 입력은 Windows API(ctypes).
#          mss·pillow가 있으면 캡처는 그쪽이 더 빠르므로 먼저 쓴다.
# Linux:   mss·pillow·pynput (없으면 pip 설치 시도, X11 필요)
UIPI_ERR = ""            # 앞 창이 관리자 권한이라 입력이 막히는 경우
INPUT_ERR = ""           # 입력이 막혔을 때 이유 — 프레임과 함께 보내 화면 창에 표시
SCREEN_ERR = ""          # 마지막 화면 오류 — heartbeat로 서버에 알려 화면 창에 표시
KEYMAP = {"Enter": "enter", "Backspace": "backspace", "Tab": "tab", "Escape": "esc", "Shift": "shift", "Control": "ctrl",
          "Alt": "alt", "Meta": "cmd", "ArrowUp": "up", "ArrowDown": "down", "ArrowLeft": "left", "ArrowRight": "right",
          "Delete": "delete", "Home": "home", "End": "end", "PageUp": "page_up", "PageDown": "page_down", "Insert": "insert",
          "CapsLock": "caps_lock", " ": "space", "ContextMenu": "menu"}
for _i in range(1, 13):
    KEYMAP[f"F{_i}"] = f"f{_i}"
VK = {"enter": 0x0D, "backspace": 0x08, "tab": 0x09, "esc": 0x1B, "shift": 0x10, "ctrl": 0x11, "alt": 0x12, "cmd": 0x5B,
      "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27, "delete": 0x2E, "home": 0x24, "end": 0x23, "page_up": 0x21,
      "page_down": 0x22, "insert": 0x2D, "caps_lock": 0x14, "space": 0x20, "menu": 0x5D, **{f"f{i}": 0x6F + i for i in range(1, 13)}}

if WIN:
    import ctypes
    from ctypes import wintypes
    try:
        ctypes.windll.user32.SetProcessDPIAware()   # 배율(125%·150%)이 걸린 화면에서도 실제 픽셀 좌표로 다룬다
    except Exception:
        pass

    class _KI(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    class _MI(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]

    class _IU(ctypes.Union):
        _fields_ = [("ki", _KI), ("mi", _MI), ("pad", ctypes.c_byte * 32)]

    class _INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _IU)]


def _win_elevated(h) -> "bool | None":
    """프로세스 핸들의 관리자 권한 여부. 일반 권한에서 관리자 프로세스의 토큰은 열 수 없으니 '접근 거부'면 관리자로 본다"""
    a, k = ctypes.windll.advapi32, ctypes.windll.kernel32
    a.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    a.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    tok = ctypes.c_void_p()
    if not a.OpenProcessToken(h, 0x0008, ctypes.byref(tok)):     # TOKEN_QUERY
        return True if k.GetLastError() == 5 else None
    try:
        elev, ret = wintypes.DWORD(), wintypes.DWORD()
        if not a.GetTokenInformation(tok, 20, ctypes.byref(elev), 4, ctypes.byref(ret)):   # TokenElevation
            return None
        return bool(elev.value)
    finally:
        k.CloseHandle(tok)


def self_elevated() -> bool:
    if not WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = ctypes.c_void_p
    return bool(_win_elevated(k.GetCurrentProcess()))


def foreground_blocked() -> str:
    """앞에 있는 창이 관리자 권한이고 이 에이전트는 아니면, Windows(UIPI)가 입력을 조용히 버린다 — 그 창 이름을 돌려준다"""
    if not WIN or SELF_ELEVATED:
        return ""
    u, k = ctypes.windll.user32, ctypes.windll.kernel32
    u.GetForegroundWindow.restype = ctypes.c_void_p
    u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    k.OpenProcess.restype = ctypes.c_void_p
    k.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)]
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    hwnd = u.GetForegroundWindow()
    if not hwnd:
        return ""
    pid = wintypes.DWORD()
    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    h = k.OpenProcess(0x1000, False, pid.value)                 # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        if not _win_elevated(h):
            return ""
        buf, n = ctypes.create_unicode_buffer(520), wintypes.DWORD(520)
        name = Path(buf.value).name if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else "관리자 권한"
        return name or "관리자 권한"
    finally:
        k.CloseHandle(h)


class WinInput:
    """Windows API로 마우스·키보드 입력 (추가 설치 없음)"""
    BTN = {0: (0x0002, 0x0004), 1: (0x0020, 0x0040), 2: (0x0008, 0x0010)}

    def __init__(self) -> None:
        self.u = ctypes.windll.user32
        self.held: set = set()
        self.buttons: set = set()

    def _send(self, *inputs) -> None:
        global INPUT_ERR
        arr = (_INPUT * len(inputs))(*inputs)
        n = self.u.SendInput(len(inputs), arr, ctypes.sizeof(_INPUT))
        if n != len(inputs):   # Windows가 입력을 막음: 관리자 권한 창이 앞에 있거나, 잠금·UAC 화면
            INPUT_ERR = "이 PC가 입력을 막았습니다 — 관리자 권한 창(작업 관리자 등)이 앞에 있거나 잠금·UAC 화면입니다"
        else:
            INPUT_ERR = ""

    def _key(self, vk: int = 0, scan: int = 0, flags: int = 0) -> "_INPUT":
        i = _INPUT(type=1); i.u.ki = _KI(vk, scan, flags, 0, 0); return i

    def _mouse(self, flags: int, data: int = 0) -> "_INPUT":
        i = _INPUT(type=0); i.u.mi = _MI(0, 0, data & 0xFFFFFFFF, flags, 0, 0); return i

    def apply(self, ev: dict, ox: int, oy: int) -> None:
        t = ev.get("type")
        if "x" in ev:
            self.u.SetCursorPos(ox + int(ev["x"]), oy + int(ev["y"]))
        if t in ("down", "up"):
            b = int(ev.get("button", 0)) if int(ev.get("button", 0)) in self.BTN else 0
            dn, upf = self.BTN[b]
            if t == "down" and b in self.buttons:      # 지난번 '뗌'을 못 받았으면 먼저 뗀다 (눌린 채 남지 않게)
                self._send(self._mouse(upf))
            self._send(self._mouse(dn if t == "down" else upf))
            (self.buttons.add if t == "down" else self.buttons.discard)(b)
        elif t == "scroll":
            dy = float(ev.get("dy", 0))
            n = max(1, round(abs(dy) / 100))
            self._send(self._mouse(0x0800, (-120 if dy > 0 else 120) * n))
        elif t == "text":
            for ch in str(ev.get("text", ""))[:200]:          # 한글 등은 유니코드 그대로 입력
                self._send(self._key(0, ord(ch), 0x0004), self._key(0, ord(ch), 0x0004 | 0x0002))
        elif t in ("keydown", "keyup"):
            name = str(ev.get("key", ""))
            up = 0x0002 if t == "keyup" else 0
            if KEYMAP.get(name):
                vk = VK[KEYMAP[name]]
                ext = 0x0001 if vk in (0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x5B, 0x5D) else 0
                self._send(self._key(vk, 0, up | ext))
                (self.held.discard if up else self.held.add)(vk)
            elif len(name) == 1:
                r = self.u.VkKeyScanW(ord(name))
                if r != -1 and (r & 0xFF) != 0xFF and not (r >> 8) & 0x6:   # 일반 키는 가상 키로 (Ctrl+C 같은 단축키가 되게)
                    vk = r & 0xFF
                    self._send(self._key(vk, 0, up))
                    (self.held.discard if up else self.held.add)(vk)
                elif not up:
                    self._send(self._key(0, ord(name), 0x0004), self._key(0, ord(name), 0x0006))

    def release_all(self) -> None:
        for vk in list(self.held):
            self._send(self._key(vk, 0, 0x0002))
        self.held.clear()
        for b in list(self.buttons):
            self._send(self._mouse(self.BTN[b][1]))
        self.buttons.clear()


class PyInput:
    """Linux 등: pynput"""
    def __init__(self) -> None:
        from pynput import mouse, keyboard
        self.mouse_mod, self.kb_mod = mouse, keyboard
        self.m, self.k = mouse.Controller(), keyboard.Controller()
        self.btn = {0: mouse.Button.left, 1: mouse.Button.middle, 2: mouse.Button.right}
        self.held: set = set()
        self.buttons: set = set()

    def apply(self, ev: dict, ox: int, oy: int) -> None:
        t = ev.get("type")
        if "x" in ev:
            self.m.position = (ox + int(ev["x"]), oy + int(ev["y"]))
        if t in ("down", "up"):
            b = self.btn.get(int(ev.get("button", 0)), self.btn[0])
            if t == "down" and b in self.buttons:
                self.m.release(b)
            (self.m.press if t == "down" else self.m.release)(b)
            (self.buttons.add if t == "down" else self.buttons.discard)(b)
        elif t == "scroll":
            dy = float(ev.get("dy", 0))
            n = max(1, round(abs(dy) / 100))
            self.m.scroll(0, -n if dy > 0 else n)
        elif t == "text":
            self.k.type(str(ev.get("text", ""))[:200])
        elif t in ("keydown", "keyup"):
            name = str(ev.get("key", ""))
            key = getattr(self.kb_mod.Key, KEYMAP[name], None) if KEYMAP.get(name) else (name if len(name) == 1 else None)
            if key is None:
                return
            if t == "keydown":
                self.k.press(key); self.held.add(key)
            else:
                self.k.release(key); self.held.discard(key)

    def release_all(self) -> None:
        for key in list(self.held):
            try:
                self.k.release(key)
            except Exception:
                pass
        self.held.clear()
        for b in list(self.buttons):
            try:
                self.m.release(b)
            except Exception:
                pass
        self.buttons.clear()


# ---- 클립보드 (텍스트만): 화면을 보는 동안 상대 PC ↔ 보는 사람 브라우저
CLIP_MAX = 100_000


def clip_get():
    try:
        if WIN:
            u, k = ctypes.windll.user32, ctypes.windll.kernel32
            u.GetClipboardData.restype = ctypes.c_void_p
            k.GlobalLock.restype = ctypes.c_void_p; k.GlobalLock.argtypes = [ctypes.c_void_p]
            k.GlobalUnlock.argtypes = [ctypes.c_void_p]
            if not u.IsClipboardFormatAvailable(13) or not u.OpenClipboard(None):   # 13 = 유니코드 텍스트
                return None
            try:
                h = u.GetClipboardData(13)
                if not h:
                    return None
                ptr = k.GlobalLock(h)
                try:
                    return ctypes.wstring_at(ptr) if ptr else None
                finally:
                    k.GlobalUnlock(h)
            finally:
                u.CloseClipboard()
        if shutil.which("xclip"):
            r = subprocess.run(["xclip", "-selection", "clipboard", "-o"], capture_output=True, timeout=2)
            return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
        if shutil.which("xsel"):
            r = subprocess.run(["xsel", "-b", "-o"], capture_output=True, timeout=2)
            return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except Exception:
        return None
    return None


def clip_set(text: str) -> bool:
    text = text[:CLIP_MAX]
    try:
        if WIN:
            u, k = ctypes.windll.user32, ctypes.windll.kernel32
            k.GlobalAlloc.restype = ctypes.c_void_p; k.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
            k.GlobalLock.restype = ctypes.c_void_p; k.GlobalLock.argtypes = [ctypes.c_void_p]
            k.GlobalUnlock.argtypes = [ctypes.c_void_p]
            u.SetClipboardData.restype = ctypes.c_void_p; u.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
            buf = ctypes.create_unicode_buffer(text)
            h = k.GlobalAlloc(0x0002, ctypes.sizeof(buf))   # GMEM_MOVEABLE
            ptr = k.GlobalLock(h)
            ctypes.memmove(ptr, buf, ctypes.sizeof(buf))
            k.GlobalUnlock(h)
            for _ in range(10):                              # 다른 프로그램이 클립보드를 잡고 있으면 잠깐 기다린다
                if u.OpenClipboard(None):
                    break
                time.sleep(0.05)
            else:
                return False
            try:
                u.EmptyClipboard()
                return bool(u.SetClipboardData(13, h))
            finally:
                u.CloseClipboard()
        tool = ["xclip", "-selection", "clipboard", "-i"] if shutil.which("xclip") else ["xsel", "-b", "-i"] if shutil.which("xsel") else None
        if not tool:
            return False
        p = subprocess.Popen(tool, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(text.encode("utf-8"), timeout=2)
        return True
    except Exception:
        return False


_CLIP = None


class ClipWatch:
    """복사가 일어나면 서버로 보낸다. 브라우저에서 받아 넣은 글은 되돌려 보내지 않는다."""
    def __init__(self, server: str, token: str) -> None:
        self.server, self.token = server, token
        self.sent = clip_get()          # 화면 보기를 시작한 시점의 내용은 보내지 않는다 (복사한 것만)
        self.last_check = 0.0
        self.retry = 0
        self.seq = ctypes.windll.user32.GetClipboardSequenceNumber() if WIN else None

    def mark(self, text: str) -> None:
        self.sent = text

    def poll(self) -> None:
        if time.time() - self.last_check < (0.3 if WIN else 1.0):
            return
        self.last_check = time.time()
        if WIN:
            seq = ctypes.windll.user32.GetClipboardSequenceNumber()
            if seq == self.seq and not self.retry:
                return
        t = clip_get()
        if t is None:
            # 복사한 프로그램이 아직 클립보드를 잡고 있으면 읽기가 실패한다 — 버리지 말고 잠시 뒤 다시 읽는다 (최대 약 3초)
            self.retry = self.retry + 1 if self.retry < 10 else 0
            if self.retry == 0:
                print("[agent] 클립보드를 읽지 못했습니다 (글자가 아닌 복사이거나 다른 프로그램이 잡고 있음)", file=sys.stderr)
                if WIN:
                    self.seq = seq
            return
        self.retry = 0
        if WIN:
            self.seq = seq
        if t == self.sent or not t.strip():
            return
        self.sent = t
        try:
            call(f"{self.server}/agent/clip", {"text": t[:CLIP_MAX]}, self.token)
            print(f"[agent] 복사한 글을 보는 사람에게 보냈습니다 ({len(t)}자)")
        except Exception as e:
            print(f"[agent] 클립보드 전송 실패: {e}", file=sys.stderr)


SELF_ELEVATED = False
_INPUT_TRIED = False


def make_input():
    """조종 도구를 만든다. 실패하면 None (보기 전용)"""
    global _INPUT_TRIED, SCREEN_ERR
    if WIN:
        return WinInput()
    for attempt in range(2):
        try:
            import importlib, site
            importlib.invalidate_caches()
            if site.getusersitepackages() not in sys.path:
                sys.path.append(site.getusersitepackages())
            return PyInput()
        except Exception as e:
            if attempt == 0 and not _INPUT_TRIED:
                _INPUT_TRIED = True
                print("[agent] 조종 모듈 설치 중 (pynput)...")
                subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--user", "pynput"], capture_output=True, timeout=180)
            else:
                SCREEN_ERR = f"조종 불가(보기만 됨): {e}"[:200]
    return None


PS_GRAB = r"""
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing,System.Windows.Forms
Add-Type -Name D -Namespace W -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'
[void][W.D]::SetProcessDPIAware()
$enc=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|Where-Object{$_.MimeType -eq 'image/jpeg'}
$ep=New-Object System.Drawing.Imaging.EncoderParameters 1
$ep.Param[0]=New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality,[long]60)
while(($l=[Console]::In.ReadLine()) -ne $null){
 try{
  $mw=[int]$l; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height
  $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size)
  $w=[Math]::Min($mw,$b.Width); $h=[int]($b.Height*$w/$b.Width)
  $s=New-Object System.Drawing.Bitmap $w,$h; $g2=[System.Drawing.Graphics]::FromImage($s)
  $g2.InterpolationMode='HighQualityBilinear'; $g2.DrawImage($bmp,0,0,$w,$h)
  $ms=New-Object IO.MemoryStream; $s.Save($ms,$enc,$ep)
  [Console]::Out.WriteLine("$($b.X) $($b.Y) $($b.Width) $($b.Height) "+[Convert]::ToBase64String($ms.ToArray()))
  $g.Dispose();$g2.Dispose();$bmp.Dispose();$s.Dispose();$ms.Dispose()
 }catch{ [Console]::Out.WriteLine("ERR "+$_.Exception.Message) }
 [Console]::Out.Flush()
}
"""


class Grabber:
    """주 모니터 → (jpeg, 원래 w, h, 화면 왼쪽 x, 위쪽 y). mss+pillow, 없으면 Windows는 PowerShell"""
    def __init__(self) -> None:
        self.ps = None
        self.sct = None
        self.last = None
        if SHOT_OK:
            self.sct = getattr(mss, "MSS", mss.mss)()
        elif WIN:
            import base64
            script = base64.b64encode(PS_GRAB.encode("utf-16-le")).decode()   # 스크립트는 인자로, stdin은 캡처 요청 전용
            self.ps = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                        "-EncodedCommand", script],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       creationflags=0x08000000)   # 창 없이
        else:
            raise RuntimeError("화면 캡처 모듈(mss, pillow)이 없고 자동 설치도 실패했습니다")

    def grab(self, max_w: int = 1280, quality: int = 60, skip_same: bool = False) -> tuple:
        """skip_same=True면 화면이 그대로일 때 jpeg 대신 None을 돌려준다 (압축·전송을 아낀다)"""
        if self.sct:
            mon = self.sct.monitors[1]
            shot = self.sct.grab(mon)
            if skip_same:
                d = hashlib.blake2b(shot.raw, digest_size=16).digest()
                if d == self.last:
                    return None, shot.width, shot.height, mon["left"], mon["top"]
                self.last = d
            img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            w, h = img.size
            if w > max_w:
                img = img.resize((max_w, int(h * max_w / w)))
            buf = io.BytesIO(); img.save(buf, "JPEG", quality=quality)
            return buf.getvalue(), w, h, mon["left"], mon["top"]
        self.ps.stdin.write(f"{max_w}\r\n".encode()); self.ps.stdin.flush()
        line = self.ps.stdout.readline().decode("ascii", "ignore").strip()
        if not line:
            raise RuntimeError("PowerShell 캡처 프로세스가 응답하지 않습니다")
        if line.startswith("ERR"):
            raise RuntimeError("PowerShell 캡처 실패: " + line[4:])
        x, y, w, h, b64 = line.split(" ", 4)
        if skip_same:
            d = hashlib.blake2b(b64.encode(), digest_size=16).digest()
            if d == self.last:
                return None, int(w), int(h), int(x), int(y)
            self.last = d
        import base64
        return base64.b64decode(b64), int(w), int(h), int(x), int(y)

    def close(self) -> None:
        try:
            if self.sct:
                self.sct.close()
            if self.ps:
                self.ps.stdin.close(); self.ps.kill()
        except Exception:
            pass


_SHOT_TRIED = False


def get_grabber() -> "Grabber":
    global _SHOT_TRIED
    if not SHOT_OK:
        _load_shot()
    if not SHOT_OK and not _SHOT_TRIED:   # 설치는 한 번만 시도 (Windows는 실패해도 PowerShell로 된다)
        _SHOT_TRIED = True
        try:
            ensure_shot_modules()
        except Exception:
            pass
    return Grabber()


def screen_loop(server: str, token: str, viewer: str, announce: bool = True, max_seconds: float = 20) -> None:
    """누군가 화면을 보는 동안 프레임을 올리고 입력을 적용한다. 20초마다 heartbeat로 돌아가 명령도 처리."""
    global SCREEN_ERR, UIPI_ERR
    try:
        grab = get_grabber()
    except Exception as e:
        SCREEN_ERR = str(e)[:200]
        print(f"[agent] 화면 보기 불가: {e}", file=sys.stderr)
        return
    inp = make_input()
    global _CLIP
    if announce or _CLIP is None:      # 새로 보기 시작할 때만 기준을 잡는다 (20초마다 이어질 때 복사를 놓치지 않게)
        _CLIP = ClipWatch(server, token)
    clip = _CLIP
    if announce:
        print(f"[agent] ⚠ '{viewer}' 계정이 이 PC 화면을 보고 있습니다 (끝나면 다시 알립니다)")
    end, ok = time.time() + max_seconds, True
    last_fg = 0.0
    last_change = time.time()
    try:
        while time.time() < end:
            t0 = time.time()
            alive()
            # 화면이 그대로면 그림 대신 '그대로' 신호만 보낸다 (서버가 마지막 그림을 유지 — 압축·전송을 아낀다)
            jpg, w, h, ox, oy = grab.grab(skip_same=True)
            jpg_send, same = (b"", "1") if jpg is None else (jpg, "0")
            req = urllib.request.Request(f"{server}/agent/frame", data=jpg_send, method="POST",
                                         headers={"Content-Type": "image/jpeg", "X-Agent-Token": token,
                                                  "X-Screen-W": str(w), "X-Screen-H": str(h), "X-Control": "1" if inp else "0",
                                                  "X-Input-Err": urllib.parse.quote(UIPI_ERR or INPUT_ERR), "X-Same": same})
            with OPENER.open(req, timeout=10) as r:
                res = json.loads(r.read())
            SCREEN_ERR = "" if inp or not SCREEN_ERR.startswith("화면") else SCREEN_ERR
            for ev in res.get("events", []):
                if ev.get("type") == "clip":            # 보는 사람이 붙여넣으려는 글 → 이 PC 클립보드에 넣는다
                    t = str(ev.get("text", ""))[:CLIP_MAX]
                    if clip_set(t):
                        clip.mark(t)
                    continue
                if ev.get("type") == "release":          # 보는 쪽이 창을 벗어나거나 조종을 끔 → 눌린 것 모두 떼기
                    if inp:
                        inp.release_all()
                    continue
                if inp:
                    try:
                        inp.apply(ev, ox, oy)
                    except Exception as e:
                        print(f"[agent] 입력 적용 실패: {e}", file=sys.stderr)
            if not res.get("continue"):
                ok = False
                break
            if res.get("need_full"):         # 서버에 그림이 없다 → 다음엔 화면이 그대로여도 전체 그림을 보낸다
                grab.last = None
            if res.get("jobs"):              # 명령이 기다리고 있으면 잠깐 빠져나가 처리한다 (화면은 곧바로 이어짐)
                break
            clip.poll()
            if WIN and time.time() - last_fg > 0.5:
                last_fg = time.time()
                try:
                    fg = foreground_blocked()
                except Exception:
                    fg = ""
                UIPI_ERR = (f"앞에 있는 '{fg}' 창이 관리자 권한이라 Windows가 원격 입력을 막습니다 — 그 창을 닫거나, "
                            "연결 프로그램을 관리자 권한으로 전환하세요") if fg else ""
            if jpg is not None or res.get("events"):
                last_change = time.time()
            # 바뀌는 동안은 약 8fps, 1초 넘게 그대로면 약 3fps로 줄여 CPU를 아낀다 (바뀌거나 조종하면 바로 다시 빠르게)
            gap = 0.12 if time.time() - last_change < 1.0 else 0.33
            time.sleep(max(0, gap - (time.time() - t0)))
    except Exception as e:
        ok = False
        SCREEN_ERR = f"화면 전송 실패: {e}"[:200]
        print(f"[agent] {SCREEN_ERR}", file=sys.stderr)
    finally:
        if inp:
            inp.release_all()
        grab.close()
    if not ok:
        print("[agent] 화면 보기가 끝났습니다")


# ----------------------------------------------------------------- 파일 탐색·가져오기 (이 PC → 메인 PC)
def clean_path(path: str) -> str:
    """복사해 온 경로의 앞뒤 따옴표·백틱·공백을 뗀다 (예: `C:\\a\\b.txt`, "C:\\a")"""
    return path.strip().strip("`'\"“”‘’").strip()


def list_dir(path: str) -> tuple[int, str]:
    p = Path(os.path.expandvars(os.path.expanduser(clean_path(path) or "~")))
    select = None
    try:
        p = p.resolve()
        if p.is_file():                     # 파일 경로를 넣으면 그 파일이 있는 폴더를 열고 그 파일을 표시
            select, p = p.name, p.parent
        items = []
        with os.scandir(p) as it:
            for e in it:
                try:
                    isdir = e.is_dir(follow_symlinks=False)
                    st = e.stat(follow_symlinks=False)
                    items.append({"name": e.name, "dir": isdir, "size": 0 if isdir else st.st_size, "mtime": int(st.st_mtime)})
                except OSError:
                    items.append({"name": e.name, "dir": False, "size": None, "mtime": None})
                if len(items) >= 3000:
                    break
    except PermissionError:
        return 1, json.dumps({"path": str(p), "error": "이 폴더에 접근할 권한이 없습니다"}, ensure_ascii=False)
    except FileNotFoundError:
        return 1, json.dumps({"path": str(p), "error": "폴더가 없습니다"}, ensure_ascii=False)
    except NotADirectoryError:
        return 1, json.dumps({"path": str(p), "error": "폴더가 아니라 파일입니다"}, ensure_ascii=False)
    except (OSError, ValueError) as e:       # 잘못된 경로 문자 등 — 멈추지 말고 이유를 돌려준다
        return 1, json.dumps({"path": str(p), "error": f"열 수 없는 경로입니다 ({getattr(e, 'strerror', None) or e})"}, ensure_ascii=False)
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")] if WIN else ["/"]
    home = str(Path.home())
    return 0, json.dumps({"path": str(p), "parent": str(p.parent) if p.parent != p else None, "items": items, "select": select,
                          "drives": drives, "home": home, "sep": os.sep, "truncated": len(items) >= 3000}, ensure_ascii=False)


def fetch_file(server: str, token: str, job: dict) -> tuple[int, str]:
    src = Path(os.path.expandvars(os.path.expanduser(clean_path(job["payload"]))))
    tmp = None
    try:
        if src.is_dir():   # 폴더는 zip으로 묶어서 보낸다
            import tempfile, zipfile
            fd, tmp = tempfile.mkstemp(suffix=".zip"); os.close(fd)
            n, total = 0, 0
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as z:
                for root, _, files in os.walk(src):
                    for f in files:
                        fp = Path(root) / f
                        alive()
                        try:
                            total += fp.stat().st_size
                            if total > 4 * 1024 ** 3:
                                return 1, "폴더가 4GB를 넘어 가져올 수 없습니다 — 더 작은 폴더나 파일을 고르세요"
                            z.write(fp, fp.relative_to(src.parent))
                            n += 1
                        except (PermissionError, OSError):
                            continue
            path, name = Path(tmp), src.name + ".zip"
        elif src.is_file():
            path, name = src, src.name
        else:
            return 1, f"없는 파일입니다: {src}"
        size = path.stat().st_size
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
                alive()
        class _Ticking:              # 큰 파일을 올리는 동안에도 지킴이에게 '살아 있음'을 알린다
            def __init__(self, f): self.f = f
            def read(self, n=-1):
                alive(); return self.f.read(n)
        with open(path, "rb") as f0:
            f = _Ticking(f0)
            req = urllib.request.Request(f"{server}/agent/upload/{job['id']}", data=f, method="POST",
                                         headers={"Content-Type": "application/octet-stream", "Content-Length": str(size),
                                                  "X-Agent-Token": token, "X-Name": urllib.parse.quote(name), "X-Sha256": h.hexdigest()})
            with OPENER.open(req, timeout=1800):
                pass
        return 0, f"가져옴: {name} ({size} bytes)"
    except urllib.error.HTTPError as e:
        return 1, f"올리기 실패: HTTP {e.code} {e.read().decode(errors='ignore')[:200]}"
    except PermissionError:
        return 1, f"읽을 권한이 없습니다: {src}"
    except Exception as e:
        return 1, f"가져오기 실패: {e}"
    finally:
        if tmp:
            Path(tmp).unlink(missing_ok=True)


def power(kind: str, dry: bool) -> tuple[int, str]:
    args = {"shutdown": ["shutdown", "/s", "/t", "5"] if WIN else ["shutdown", "-h", "now"],
            "reboot": ["shutdown", "/r", "/t", "5"] if WIN else ["shutdown", "-r", "now"]}[kind]
    if dry:
        return 0, f"(dry-run) {' '.join(args)}"
    subprocess.Popen(args)
    return 0, f"실행: {' '.join(args)}"


# ----------------------------------------------------------------- 자동 업데이트
FROZEN = bool(getattr(sys, "frozen", False))      # exe로 묶은 경우는 자동 업데이트하지 않는다
try:
    AGENT_SHA = "" if FROZEN else hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
except Exception:
    AGENT_SHA = ""
_UPDATE_TRIED: set = set()


def self_update(server: str, want: str) -> None:
    """메인 PC의 agent.py가 바뀌었으면 받아서 바꾸고 다시 시작한다 (해시가 맞을 때만)"""
    if FROZEN or not AGENT_SHA or want in _UPDATE_TRIED:
        return
    _UPDATE_TRIED.add(want)
    me = Path(__file__).resolve()
    try:
        with OPENER.open(f"{server}/download/agent.py", timeout=30) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != want:
            print("[agent] 업데이트 파일의 해시가 달라 건너뜁니다", file=sys.stderr)
            return
        compile(data, "agent.py", "exec")            # 문법이 깨진 파일이면 바꾸지 않는다
        tmp = me.with_suffix(".py.new")
        tmp.write_bytes(data)
        bak = me.with_suffix(".py.bak")
        try:
            bak.write_bytes(me.read_bytes())
        except Exception:
            pass
        os.replace(tmp, me)
    except Exception as e:
        print(f"[agent] 자동 업데이트 실패: {e}", file=sys.stderr)
        return
    try:   # 곧 종료하므로 출력 쓰레드를 거치지 않고 바로 쓴다
        sys.__stdout__.write("[agent] 새 버전을 받았습니다 — 다시 시작합니다\n"); sys.__stdout__.flush()
    except Exception:
        pass
    if os.environ.get("PCM_CHILD"):
        os._exit(3)                   # 지킴이가 새 파일로 바로 다시 띄운다
    args = [sys.executable, str(me)] + [a for a in sys.argv[1:]]
    if WIN:
        subprocess.Popen(args)        # 같은 창에서 새 프로세스로 이어서 실행
        os._exit(0)
    os.execv(sys.executable, args)


def run_job(job: dict, server: str, token: str, a) -> tuple[int, str]:
    kind = job["kind"]
    if kind == "shell":
        return run_shell(job["payload"])
    if kind == "file":
        return download(server, token, job)
    if kind == "screenshot":
        return screenshot(server, token, job["id"])
    if kind == "ls":
        return list_dir(job["payload"])
    if kind == "fetch":
        return fetch_file(server, token, job)
    if kind == "elevate":
        return elevate_request()
    if kind in ("shutdown", "reboot"):
        return power(kind, a.dry_run)
    return 1, "모르는 명령"


class JobRunner:
    """명령을 메인 루프와 따로 실행한다. 메인 루프는 계속 '살아 있음'을 보내고 화면을 전송한다.
    오래 걸리는 일(명령 실행·파일 전송·캡처·전원)과 빠른 일(폴더 목록 등)을 다른 줄에 세워
    긴 설치 명령이 도는 중에도 파일 창이 바로 열리게 한다. 각 줄 안에서는 받은 순서대로 처리한다."""
    FAST = {"ls", "elevate"}

    def __init__(self) -> None:
        import queue as _q
        self.qs = {"slow": _q.Queue(), "fast": _q.Queue()}
        for name, q in self.qs.items():
            threading.Thread(target=self._work, args=(q,), daemon=True, name=f"jobs-{name}").start()

    def submit(self, job: dict, server: str, token: str, a) -> None:
        print(f"[agent] 명령 #{job['id']} {job['kind']}: {job['payload'][:80]}")
        self.qs["fast" if job["kind"] in self.FAST else "slow"].put((job, server, token, a))

    def _work(self, q) -> None:
        while True:
            job, server, token, a = q.get()
            try:
                code, out = run_job(job, server, token, a)
            except Exception as e:      # 어떤 오류든 '실행 중'으로 남기지 않고 실패로 보고한다
                code, out = 1, f"연결 프로그램 오류: {type(e).__name__}: {e}"
                log_crash(f"명령 #{job['id']} {job['kind']} 처리 중 오류\n" + __import__("traceback").format_exc())
            for attempt in range(5):    # 결과 보고가 잠깐 실패해도(서버 재시작 등) 몇 번 더 시도
                try:
                    call(f"{server}/agent/result", {"command_id": job["id"], "exit_code": code, "output": out}, token)
                    break
                except Exception as e:
                    if attempt == 4:
                        print(f"[agent] 결과 전송 실패 #{job['id']}: {e}", file=sys.stderr)
                    time.sleep(2)


RUNNER: "JobRunner"


def install_autostart() -> bool:
    """로그인 시 자동 실행 등록 (관리자 권한 불필요). Windows: HKCU Run 키, Linux: systemd --user"""
    me = Path(sys.argv[0]).resolve()
    cmd = f'"{me}"' if me.suffix.lower() == ".exe" else f'"{sys.executable}" "{me}"'
    if WIN:
        r = subprocess.run(["reg", "add", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "PCManagerAgent",
                            "/t", "REG_SZ", "/d", cmd, "/f"], capture_output=True)
        ok = r.returncode == 0
        print("[agent] 자동 시작 등록 " + ("완료 (다음 로그인부터 자동 실행)" if ok else f"실패: {r.stderr.decode('cp949', 'replace').strip()}"))
        return ok
    unit = Path.home() / ".config/systemd/user/pcmanager-agent.service"
    unit.parent.mkdir(parents=True, exist_ok=True)
    unit.write_text(f"[Unit]\nDescription=PCmoa agent\n[Service]\nExecStart={cmd}\nRestart=always\n[Install]\nWantedBy=default.target\n")
    r = subprocess.run(["systemctl", "--user", "enable", "--now", "pcmanager-agent"], capture_output=True)
    print(f"[agent] systemd 사용자 서비스 등록: {unit}" + ("" if r.returncode == 0 else " (systemctl 실패 — 로그인 시 수동 실행 필요)"))
    return r.returncode == 0


def elevate_request(wait: bool = False) -> tuple[int, str]:
    """관리자 권한으로 다시 등록·실행하도록 UAC 창을 띄운다 (그 PC 앞에서 '예'를 눌러야 함)"""
    if not WIN:
        return 1, "Windows에서만 됩니다"
    if SELF_ELEVATED:
        return 0, "이미 관리자 권한으로 실행 중입니다"
    if FROZEN:
        exe, params = sys.executable, "--install-admin"
    else:
        exe, params = sys.executable, f'"{Path(__file__).resolve()}" --install-admin'
    def ask() -> None:
        # ShellExecute(runas)는 UAC 창에 답할 때까지 돌아오지 않는다 → 따로 돌려야 연결(heartbeat)이 끊기지 않는다
        sh = ctypes.windll.shell32
        sh.ShellExecuteW.restype = ctypes.c_void_p
        r = sh.ShellExecuteW(None, "runas", exe, params, str(HERE), 1)
        if (r or 0) <= 32:
            print("[agent] 관리자 권한 전환이 취소됐거나 실패했습니다" + (" (UAC에서 '아니요')" if r == 5 else f" (코드 {r})"), file=sys.stderr)
        else:
            print("[agent] 관리자 권한 전환을 승인했습니다 — 곧 관리자 권한으로 다시 시작됩니다")
    if wait:          # 명령줄(--install-admin)에서는 답을 기다린다
        ask()
        return 0, "UAC 응답을 처리했습니다"
    threading.Thread(target=ask, daemon=True).start()
    return 0, "그 PC 화면에 UAC 확인 창을 띄웠습니다 — 그 PC 앞에서 '예'를 눌러야 합니다(원격으로는 누를 수 없음). 기다리는 동안에도 연결은 유지됩니다"


def install_admin() -> None:
    """관리자 권한으로 실행된 상태에서: 로그인 때 '가장 높은 권한'으로 자동 실행되는 작업을 만들고 바로 바꿔 띄운다"""
    if not WIN:
        print("[agent] --install-admin은 Windows 전용입니다 (Linux는 X11 세션의 사용자 권한으로 조종됩니다)")
        return
    if not self_elevated():
        code, msg = elevate_request(wait=True)
        return
    me = Path(sys.argv[0]).resolve()
    tr = f'"{me}"' if me.suffix.lower() == ".exe" else f'"{sys.executable}" "{me}"'
    user = os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")
    r = subprocess.run(["schtasks", "/Create", "/TN", "PCManagerAgent", "/TR", tr, "/SC", "ONLOGON", "/RL", "HIGHEST",
                        "/IT", "/RU", user, "/F"], capture_output=True)
    if r.returncode != 0:
        print("[agent] 작업 스케줄러 등록 실패: " + r.stderr.decode("cp949", "replace").strip())
        input("Enter를 누르면 닫힙니다")
        return
    # 일반 권한 자동 시작은 지워야 그쪽이 먼저 떠서 자리를 차지하지 않는다
    subprocess.run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "PCManagerAgent", "/f"], capture_output=True)
    # 지금 떠 있는 일반 권한 에이전트를 끄고 관리자 권한으로 바로 시작
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^python' -and $_.CommandLine -match 'agent\\.py' -and "
          f"$_.ProcessId -ne {os.getpid()} }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True)
    time.sleep(1)
    subprocess.run(["schtasks", "/Run", "/TN", "PCManagerAgent"], capture_output=True)
    print("[agent] 관리자 권한 자동 실행을 등록하고 다시 시작했습니다. 이제 관리자 권한 창도 조종할 수 있습니다.")
    time.sleep(3)


def uninstall() -> None:
    """이 PC에서 연결 프로그램을 걷어 낸다: 자동 시작 해제 → 실행 중인 연결 프로그램 종료 → 등록 정보(agent.json) 삭제.
    메인 PC 목록의 카드는 대시보드에서 따로 지운다(⋯ → 목록에서 삭제)."""
    me = os.getpid()
    print("[uninstall] 1/3 자동 시작 해제")
    if WIN:
        r = subprocess.run(["reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "PCManagerAgent", "/f"],
                           capture_output=True)
        print("  - 로그인 자동 실행(레지스트리): " + ("지움" if r.returncode == 0 else "없음"))
        q = subprocess.run(["schtasks", "/Query", "/TN", "PCManagerAgent"], capture_output=True)
        if q.returncode == 0:
            d = subprocess.run(["schtasks", "/Delete", "/TN", "PCManagerAgent", "/F"], capture_output=True)
            if d.returncode == 0:
                print("  - 관리자 권한 자동 실행(작업 스케줄러): 지움")
            else:
                print("  - 관리자 권한 자동 실행(작업 스케줄러): 권한이 없어 못 지움")
                print("    → 관리자 PowerShell에서:  schtasks /Delete /TN PCManagerAgent /F")
        else:
            print("  - 관리자 권한 자동 실행(작업 스케줄러): 없음")
    else:
        unit = Path.home() / ".config/systemd/user/pcmanager-agent.service"
        subprocess.run(["systemctl", "--user", "disable", "--now", "pcmanager-agent"], capture_output=True)
        if unit.exists():
            unit.unlink()
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
            print(f"  - systemd 사용자 서비스: 지움 ({unit})")
        else:
            print("  - systemd 사용자 서비스: 없음")

    print("[uninstall] 2/3 실행 중인 연결 프로그램 종료")
    killed = 0
    for _ in range(2):   # 지킴이가 자식을 다시 띄울 틈이 없게 두 번 훑는다
        if WIN:
            ps = ("Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne " + str(me) + " -and "
                  "(($_.Name -match '^python' -and $_.CommandLine -match 'agent\\.py') -or $_.Name -eq 'pcmanager-agent.exe') } | "
                  "ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $_.ProcessId }")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True).stdout
            killed += len([x for x in out.split() if x.strip().isdigit()])
        else:
            out = subprocess.run(["pgrep", "-f", r"agent\.py"], capture_output=True, text=True).stdout
            for pid in (int(x) for x in out.split() if x.isdigit()):
                if pid in (me, os.getppid()):
                    continue
                try:
                    os.kill(pid, 9)
                    killed += 1
                except OSError:
                    pass
        time.sleep(1)
    print(f"  - 종료한 프로세스: {killed}개")

    print("[uninstall] 3/3 등록 정보 삭제")
    for f in (STATE, HERE / "agent.alive"):
        if f.exists():
            f.unlink()
            print(f"  - 지움: {f}")
    print()
    print("[uninstall] 끝. 남은 일:")
    print(f"  1) 이 폴더를 통째로 지우면 프로그램이 완전히 사라집니다: {HERE}")
    print("  2) 메인 PC 대시보드에서 이 PC 카드의 ⋯ → '목록에서 삭제'")


def rejoin(server: str, old_token: str, hostname: str, mac: str, osname: str, host: str):
    """토큰이 안 맞을 때: 같은 PC가 목록에 남아 있으면 코드 없이 새 토큰을 받는다"""
    try:
        res = call(f"{server}/agent/rejoin", {"old_token": old_token or "", "hostname": hostname,
                                               "ip": local_ip(host), "mac": mac, "os": osname})
        STATE.write_text(json.dumps({"server": server, "agent_token": res["agent_token"], "pc_id": res["pc_id"]}))
        print(f"[agent] 토큰이 바뀌어 있어 '{res.get('name', hostname)}'으로 자동 재연결했습니다")
        return res["agent_token"]
    except urllib.error.HTTPError:
        print("[agent] 메인 PC 목록에 이 PC가 없습니다 (삭제됨) — 새 연결 코드가 필요합니다")
        return None
    except Exception as e:
        print(f"[agent] 재연결 실패: {e}", file=sys.stderr)
        return None


_LOCK_SOCK = None


def single_instance(port: int = 47651, wait: float = 15) -> bool:
    """이 PC에서 에이전트가 하나만 돌게 한다 (자동 시작 + 손으로 실행이 겹치는 경우).
    자동 업데이트로 다시 시작할 때는 이전 프로세스가 끝날 때까지 잠깐 기다린다."""
    global _LOCK_SOCK
    end = time.time() + wait
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if WIN:
            s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", -5), 1)
        try:
            s.bind(("127.0.0.1", port))
            s.listen(1)
            _LOCK_SOCK = s
            return True
        except OSError:
            s.close()
            if time.time() > end:
                return False
            time.sleep(0.5)


_INHIBIT_PROC = None
_AWAKE_WANT = [True]   # 마지막으로 서버가 원한 값
AWAKE = ""        # 절전 막기 상태 — heartbeat로 서버에 알린다: "on" · "off" · "fail:<이유>"


def keep_awake() -> str:
    """연결 프로그램이 켜져 있는 동안 PC가 절전(대기)에 들어가지 않게 한다. 화면 끄기는 막지 않는다.
    프로그램이 꺼지면(정상 종료·강제 종료 모두) OS가 알아서 풀어 준다. 결과를 한 줄로 돌려준다."""
    global _INHIBIT_PROC
    if WIN:
        # ES_CONTINUOUS | ES_SYSTEM_REQUIRED — 이 스레드(메인 반복)가 살아 있는 동안 유지
        try:
            import ctypes
            if ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001):
                return "켜짐"
            return "실패(SetThreadExecutionState)"
        except Exception as e:
            return f"실패({e})"
    # Linux: systemd-inhibit로 절전을 막는다. 'tail --pid'는 이 프로세스가 죽으면 같이 끝나 막기가 풀린다
    if not shutil.which("systemd-inhibit"):
        return "건너뜀(systemd-inhibit 없음)"
    try:
        _INHIBIT_PROC = subprocess.Popen(
            ["systemd-inhibit", "--what=sleep", "--who=PCmoa", "--why=PCmoa 연결 유지", "--mode=block",
             "tail", f"--pid={os.getpid()}", "-f", "/dev/null"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        if _INHIBIT_PROC.poll() is not None:     # 권한(polkit) 등으로 바로 끝났으면 실패
            return "실패(권한 없음일 수 있음)"
        return "켜짐"
    except Exception as e:
        return f"실패({e})"


def allow_sleep() -> None:
    """절전 막기 해제 (종료할 때)."""
    if WIN:
        try:
            import ctypes
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        except Exception:
            pass
    elif _INHIBIT_PROC and _INHIBIT_PROC.poll() is None:
        try:
            _INHIBIT_PROC.terminate()
        except Exception:
            pass


def awake_retry() -> None:
    global AWAKE
    if AWAKE.startswith("fail"):
        AWAKE = ""


def apply_awake(want: bool, why_off: str = "") -> None:
    """절전 막기를 원하는 상태로 맞춘다. 실패한 상태는 원하는 값이 바뀔 때만 다시 시도한다 (5초마다 재시도하지 않게).
    반드시 메인 반복을 도는 스레드에서 부른다 — Windows는 부른 스레드가 살아 있는 동안만 유지된다."""
    global AWAKE, _INHIBIT_PROC
    if want:
        if AWAKE == "on" or AWAKE.startswith("fail"):
            return
        r = keep_awake()
        AWAKE = "on" if r == "켜짐" else "fail:" + r
        print(f"[agent] 절전 막기: {r}" + (" — 연결 프로그램이 켜져 있는 동안 이 PC는 절전에 들어가지 않습니다 (화면 꺼짐은 그대로)"
                                         if r == "켜짐" else " — 절전에 들어가면 대시보드에 '응답 없음'으로 보일 수 있습니다"))
    else:
        target = "fail:" + why_off if why_off else "off"
        if AWAKE == target:
            return
        if AWAKE == "on":
            allow_sleep()
            _INHIBIT_PROC = None
            print("[agent] 절전 막기: 꺼짐 — 이 PC는 원래 전원 설정대로 절전에 들어갑니다")
        AWAKE = target


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", help="예: http://192.168.0.10:8000 (생략하면 물어봄)")
    ap.add_argument("--code", help="메인 PC 화면의 6자리 연결 코드")
    ap.add_argument("--enroll", help="관리자용 등록 토큰 (코드 대신)")
    ap.add_argument("--install", action="store_true", help="로그인 시 자동 실행 등록")
    ap.add_argument("--register", action="store_true", help="등록(+자동 시작)만 하고 종료 — 설치 스크립트용")
    ap.add_argument("--interval", type=float, default=5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-screen", action="store_true", help="이 PC의 화면 보기·조종을 거부")
    ap.add_argument("--no-update", action="store_true", help="메인 PC의 새 버전으로 자동 업데이트하지 않음")
    ap.add_argument("--allow-sleep", action="store_true", help="연결 중에도 이 PC가 절전에 들어가도 됨 (기본: 연결 중 절전 막기)")
    ap.add_argument("--install-admin", action="store_true", help="(Windows) 관리자 권한으로 자동 실행 — 관리자 권한 창도 조종 가능")
    ap.add_argument("--uninstall", action="store_true", help="이 PC에서 연결 프로그램 걷어 내기 (자동 시작 해제·종료·등록 정보 삭제)")
    a = ap.parse_args()
    if a.uninstall:
        uninstall()
        return
    if a.install_admin:
        install_admin()
        return

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    server = (a.server or state.get("server") or "").rstrip("/")
    if not server:
        server = input("메인 PC 주소 (예: http://192.168.0.10:8000): ").strip().rstrip("/")
        if not server.startswith("http"):
            server = "http://" + server
        if server.count(":") < 2:
            server += ":8000"
    host = server.split("://", 1)[-1].split("/")[0].split(":")[0]
    hostname, mac, osname = socket.gethostname(), local_mac(), f"{platform.system()} {platform.release()}"

    token = state.get("agent_token") if state.get("server") == server else None
    if token and not a.enroll:
        # 이미 등록된 PC: 저장된 토큰이 유효하면 코드가 있어도(만료됐어도) 그냥 연결한다
        try:
            call(f"{server}/agent/heartbeat", {"hostname": hostname, "os": osname, **metrics()}, token)
            if a.code:
                print("[agent] 이미 등록된 PC입니다 — 저장된 토큰으로 연결합니다 (연결 코드는 쓰지 않음)")
            a.code = None
        except urllib.error.HTTPError as e:
            if e.code == 401:
                token = rejoin(server, token, hostname, mac, osname, host)
            else:
                print(f"[agent] 메인 PC 서버 응답 오류 {e.code} — 그대로 연결을 시도합니다", file=sys.stderr)
                a.code = None
        except Exception as e:
            # 메인 PC 서버가 아직 안 켜졌거나 재시작 중 → 끄지 말고 기다렸다가 붙는다 (아래 반복에서 계속 시도)
            print(f"[agent] 메인 PC({server})에 아직 연결할 수 없습니다: {e} — 연결될 때까지 계속 시도합니다", file=sys.stderr)
            a.code = None
    if a.enroll or a.code or not token:
        if a.enroll:
            res = call(f"{server}/agent/enroll", {"enroll_token": a.enroll, "hostname": hostname,
                                                   "ip": local_ip(host), "mac": mac, "os": osname})
        else:
            try:
                code = a.code or input("연결 코드 6자리 (메인 PC 화면의 'PC 연결'에서 발급): ").strip()
            except EOFError:
                print("[agent] 등록이 필요합니다. 메인 PC에서 ⚡ PC 연결 → 새 코드를 발급해 다시 실행하세요"); sys.exit(2)
            if not code:
                print("[agent] 코드가 없어 종료합니다. 메인 PC에서 새 코드를 발급해 다시 실행하세요"); sys.exit(2)
            try:
                res = call(f"{server}/agent/pair", {"code": code, "hostname": hostname,
                                                     "ip": local_ip(host), "mac": mac, "os": osname})
            except urllib.error.HTTPError as e:
                print("[agent] 등록 실패: " + e.read().decode(errors="ignore")); sys.exit(2)
            except Exception as e:
                sys.exit(f"[agent] 메인 PC에 연결할 수 없습니다 ({server}): {e}")
        token = res["agent_token"]
        STATE.write_text(json.dumps({"server": server, "agent_token": token, "pc_id": res["pc_id"]}))
        print(f"[agent] 등록 완료: '{res.get('name', hostname)}' (pc_id={res['pc_id']}) — 토큰은 {STATE.name}에 저장")
        if WIN and not a.install and sys.stdin.isatty():
            if input("PC를 켤 때 자동으로 연결되게 할까요? [Y/n] ").strip().lower() in ("", "y"):
                install_autostart()
    ok = True
    if a.install or a.register:
        ok = install_autostart()
    if a.register:
        print("[agent] 등록 완료." + (" PC를 켤 때 자동으로 연결됩니다." if ok else " 자동 시작은 등록하지 못해, 연결하려면 이 프로그램을 다시 실행해야 합니다."))
        print(f"[agent] 이 PC에서도 대시보드를 볼 수 있습니다: {server}  (브라우저 메뉴에서 '앱 설치' 가능)")
        return
    global SELF_ELEVATED
    SELF_ELEVATED = self_elevated()
    if SELF_ELEVATED and WIN:
        print("[agent] 관리자 권한으로 실행 중 — 관리자 권한 창(작업 관리자 등)도 조종할 수 있습니다")
    if not single_instance():
        print("[agent] 이 PC에서 연결 프로그램이 이미 실행 중입니다 — 이 창은 닫아도 됩니다"); sys.exit(4)
    print(f"[agent] {hostname} ({osname}) → {server}  (이 창을 닫으면 연결이 끊깁니다)")
    # 절전 막기: 처음엔 켜 두고, 이후로는 대시보드(관리 메뉴)에서 정한 값을 heartbeat로 받아 따른다
    apply_awake(not a.allow_sleep, "이 PC에서 --allow-sleep으로 실행 중" if a.allow_sleep else "")
    import atexit
    atexit.register(allow_sleep)
    INBOX.mkdir(parents=True, exist_ok=True)   # 명령의 작업 폴더이자 받은 파일 저장 위치
    last_term = 0.0
    screening = False
    fast = False
    global RUNNER
    RUNNER = JobRunner()
    threading.Thread(target=lambda: SHELLS.extend(detect_shells()), daemon=True).start()   # 쓸 수 있는 셸 찾기 (한 번)

    while True:
        alive()
        try:
            res = call(f"{server}/agent/heartbeat", {"hostname": hostname, "os": osname, **metrics(),
                                                      "version": AGENT_SHA[:12], "screen_err": SCREEN_ERR,
                                                      "screen_off": a.no_screen, "last_crash": os.environ.pop("PCM_LAST_CRASH", ""),
                                                      "shells": SHELLS, "awake": AWAKE}, token)
            want_awake = bool(res.get("keep_awake", True))   # 대시보드 관리 메뉴의 '연결 중 절전 막기'
            if a.allow_sleep:
                apply_awake(False, "이 PC에서 --allow-sleep으로 실행 중" if want_awake else "")
            else:
                if want_awake and not _AWAKE_WANT[0]:
                    awake_retry()             # 껐다가 다시 켜면 실패했던 것도 한 번 더 시도
                apply_awake(want_awake)
            _AWAKE_WANT[0] = want_awake
            if res.get("agent_sha") and AGENT_SHA and res["agent_sha"] != AGENT_SHA and not a.no_update:
                self_update(server, res["agent_sha"])
            if res.get("term"):
                term_loop(server, token)
                last_term = time.time()
                continue
            want_screen = bool(res.get("screen")) and not a.no_screen
            fast = bool(res.get("fast"))
            WATCHED[0] = bool(res.get("watched", True))
            if SHELL is not None and time.time() - last_term > 120:   # 터미널을 2분 안 쓰면 셸을 닫아 메모리를 돌려준다
                SHELL.close()
                globals()["SHELL"] = None
            for job in res.get("commands", []):
                RUNNER.submit(job, server, token, a)   # 명령은 따로 도는 일꾼이 처리 — 오래 걸려도 연결·화면이 끊기지 않게
            if want_screen:                 # 받은 명령을 먼저 처리한 뒤 화면 전송 (화면을 보는 중에도 명령이 밀리지 않게)
                screen_loop(server, token, res.get("viewer", ""), announce=not screening)
            screening = want_screen
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="ignore")
            print(f"[agent] 서버 거부 {e.code}: {msg}", file=sys.stderr)
            if e.code == 401:
                new = rejoin(server, token, hostname, mac, osname, host)
                if new:
                    token = new
                    continue
                STATE.unlink(missing_ok=True)
                print("[agent] 메인 PC에 이 PC의 등록이 없습니다 (목록에서 삭제됐거나 토큰 재발급).", file=sys.stderr)
                print("[agent] 메인 PC에서 ⚡ PC 연결 → 새 코드를 발급해 다시 실행하세요.", file=sys.stderr)
                if sys.stdin.isatty():
                    code = input("새 연결 코드 6자리 (없으면 Enter로 종료): ").strip()
                    if code:
                        os.execv(sys.executable, [sys.executable, str(Path(sys.argv[0]).resolve()), "--server", server, "--code", code, "--install"])
                sys.exit(2)
        except Exception as e:
            print(f"[agent] 서버 연결 실패: {e}", file=sys.stderr)
        time.sleep(0.1 if screening else 0.3 if fast else a.interval)   # 파일 탐색 중이면 빠르게 응답   # 화면을 보는 중이면 바로 이어서 전송


# ----------------------------------------------------------------- 지킴이: 오류로 꺼지면 다시 띄운다
LOG = HERE / "agent.log"
HANG_SECONDS = int(os.environ.get("PCM_HANG_SECONDS", "120"))


def disable_quickedit() -> None:
    """Windows 콘솔의 '빠른 편집'을 끈다 — 켜져 있으면 창을 클릭하는 순간 프로그램 전체가 멈춘다(Enter를 눌러야 풀림)"""
    if not WIN:
        return
    try:
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-10)
        mode = wintypes.DWORD()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, (mode.value | 0x0080) & ~0x0040)   # ENABLE_EXTENDED_FLAGS, QuickEdit 끄기
    except Exception:
        pass


def log_crash(text: str) -> None:
    try:
        if LOG.exists() and LOG.stat().st_size > 1_000_000:
            LOG.replace(LOG.with_suffix(".log.old"))
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')}\n{text}\n")
    except Exception:
        pass


# (지킴이는 파일 맨 위에서 무거운 모듈을 불러오기 전에 시작한다)


if __name__ == "__main__":
    disable_quickedit()
    one_shot = any(x in sys.argv for x in ("--register", "--install-admin", "--uninstall", "-h", "--help"))
    if os.environ.get("PCM_CHILD") or one_shot:
        if os.environ.get("PCM_CHILD"):
            _nonblocking_print()
        try:
            main()
        except SystemExit:
            raise
        except BaseException:
            import traceback
            log_crash(traceback.format_exc())
            raise
    else:   # 지킴이는 맨 위에서 이미 처리됨 — 여기 오면 자식으로 실행
        main()
