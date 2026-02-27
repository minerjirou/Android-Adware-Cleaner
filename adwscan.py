#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
adwscan.py
ADB + logcat("Displayed") を使った Android 向けアドウェア調査/隔離/削除支援ツール（Windows向け）
- monitor      : Displayedイベント監視
- inventory    : ユーザーアプリ一覧
- inspect      : パッケージ詳細調査 + スコアリング
- quarantine   : force-stop + disable-user
- remove       : force-stop + disable-user + uninstall --user 0
- restore      : enable + install-existing
- auto         : Displayed監視 + スコアリング + 段階的対処（既定は dry-run）
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Deque, Dict, List, Optional


# =========================
# Config / Defaults
# =========================

APP_NAME = "adwscan"
ADB_BIN = "adb"

# ===== thresholds (HiddenAds向けに少し厳しめ) =====
DEFAULT_WARN_THRESHOLD = 45
DEFAULT_QUAR_THRESHOLD = 80
DEFAULT_REMOVE_THRESHOLD = 105

# 最低限の既定 allowlist（機種差あり）
BUILTIN_ALLOWLIST_PREFIXES = (
    "com.android.",
    "com.google.android.",
    "com.google.",
    "android.",
)
BUILTIN_ALLOWLIST_EXACT = {
    "com.android.systemui",
    "com.android.settings",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.packageinstaller",
    "com.android.packageinstaller",
}

# Displayed ログを拾う（ActivityTaskManager / ActivityManager）
DISPLAYED_RE = re.compile(
    r"Displayed\s+([A-Za-z0-9._]+)/([A-Za-z0-9.$_/\-]+)"
)

# 追加の弱いシグナル（任意）
SUSPICIOUS_NAME_RE = re.compile(
    r"(ad|ads|advert|offer|promo|boost|cleaner|junk|speed|battery|vpn|browser)",
    re.IGNORECASE,
)

# ===== permissions / appops signals =====
PERM_SIGNALS = {
    "SYSTEM_ALERT_WINDOW": 35,          # overlay（強）
    "BIND_ACCESSIBILITY_SERVICE": 35,   # accessibility（強）
    "PACKAGE_USAGE_STATS": 15,          # 前景追跡に使われやすい
    "RECEIVE_BOOT_COMPLETED": 12,       # 永続化/再起動後起動
    "FOREGROUND_SERVICE": 8,            # 常駐の弱いシグナル
    "POST_NOTIFICATIONS": 5,            # 通知広告の弱いシグナル
    "WAKE_LOCK": 5,
    "REQUEST_INSTALL_PACKAGES": 20,     # adwareよりdropper寄りだが要監視
}

APPOPS_SIGNALS = {
    "SYSTEM_ALERT_WINDOW": 25,  # 許可済み overlay
    "GET_USAGE_STATS": 15,      # Usage Access
    "REQUEST_INSTALL_PACKAGES": 10,
}

# ===== dumpsys package テキストから拾う挙動シグナル =====
BEHAVIOR_TEXT_SIGNALS = {
    "android.intent.action.BOOT_COMPLETED": ("BOOT_COMPLETED receiver/intent", 15),
    "android.intent.action.USER_PRESENT": ("USER_PRESENT receiver/intent", 20),
    "INSTALL_SHORTCUT": ("shortcut creation behavior", 10),
    "android.intent.action.PACKAGE_ADDED": ("PACKAGE_ADDED receiver/intent", 8),
    "android.intent.action.PACKAGE_REPLACED": ("PACKAGE_REPLACED receiver/intent", 8),
}


# =========================
# Data classes
# =========================

@dataclasses.dataclass
class Event:
    ts: float
    pkg: str
    activity: str
    raw: str


@dataclasses.dataclass
class ScoreResult:
    pkg: str
    score: int
    reasons: List[str]
    details: Dict[str, object]


# =========================
# Utility functions
# =========================

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def now_ts() -> float:
    return time.time()


def ts_iso(ts: Optional[float] = None) -> str:
    if ts is None:
        ts = now_ts()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data):
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# =========================
# ADB wrapper
# =========================

class ADB:
    def __init__(self, adb_bin: str = ADB_BIN, serial: Optional[str] = None, verbose: bool = False):
        self.adb_bin = adb_bin
        self.serial = serial
        self.verbose = verbose

    def _base_cmd(self) -> List[str]:
        cmd = [self.adb_bin]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(self, *args: str, timeout: int = 20, check: bool = False) -> subprocess.CompletedProcess:
        cmd = self._base_cmd() + list(args)
        if self.verbose:
            eprint("[ADB]", " ".join(cmd))
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        if check and cp.returncode != 0:
            raise RuntimeError(
                f"ADB command failed ({cp.returncode}): {' '.join(cmd)}\n"
                f"STDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}"
            )
        return cp

    def shell(self, *args: str, timeout: int = 20, check: bool = False) -> subprocess.CompletedProcess:
        return self.run("shell", *args, timeout=timeout, check=check)

    def device_state(self) -> str:
        cp = self.run("get-state", timeout=10)
        return (cp.stdout or cp.stderr).strip()

    def ensure_device(self):
        state = self.device_state()
        if "device" not in state:
            raise RuntimeError(
                f"ADB device not ready: {state!r}. USB debugging / authorization / adb devices を確認してください。"
            )

    def kill_server(self):
        # adwscan 終了時に adb プロセスを残さない
        self.run("kill-server", timeout=10)


# =========================
# Core tool
# =========================

class AdwScan:
    def __init__(self, adb: ADB, base_dir: Optional[Path] = None):
        self.adb = adb
        if base_dir is None:
            base_dir = Path(os.environ.get("USERPROFILE", str(Path.home()))) / f".{APP_NAME}"
        self.base_dir = base_dir
        ensure_dir(self.base_dir)

        self.allowlist_path = self.base_dir / "allowlist.json"
        self.state_path = self.base_dir / "state.json"
        self.events_log_path = self.base_dir / "events.ndjson"

        self.allowlist = self._load_allowlist()
        self.state = load_json(self.state_path, {"actioned": {}, "last_seen": {}})

        self.events_by_pkg: Dict[str, Deque[Event]] = collections.defaultdict(lambda: collections.deque(maxlen=500))

    # ---------- Allowlist / State ----------
    def _load_allowlist(self) -> Dict[str, object]:
        default_data = {
            "exact": sorted(BUILTIN_ALLOWLIST_EXACT),
            "prefixes": list(BUILTIN_ALLOWLIST_PREFIXES),
        }
        data = load_json(self.allowlist_path, default_data)
        if "exact" not in data:
            data["exact"] = default_data["exact"]
        if "prefixes" not in data:
            data["prefixes"] = default_data["prefixes"]
        if not self.allowlist_path.exists():
            save_json(self.allowlist_path, data)
        return data

    def save_state(self):
        save_json(self.state_path, self.state)

    def append_event_log(self, evt: Event):
        line = json.dumps({
            "ts": evt.ts,
            "time": ts_iso(evt.ts),
            "pkg": evt.pkg,
            "activity": evt.activity,
            "raw": evt.raw,
        }, ensure_ascii=False)
        with self.events_log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def is_allowlisted(self, pkg: str) -> bool:
        if pkg in set(self.allowlist.get("exact", [])):
            return True
        for pfx in self.allowlist.get("prefixes", []):
            if pkg.startswith(pfx):
                return True
        return False

    # ---------- Inventory ----------
    def list_user_packages(self) -> List[str]:
        cp = self.adb.shell("pm", "list", "packages", "-3", timeout=30)
        pkgs = []
        for line in cp.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                pkgs.append(line.split(":", 1)[1].strip())
        return sorted(set(pkgs))

    def cmd_inventory(self, json_out: bool = False):
        pkgs = self.list_user_packages()
        if json_out:
            print(json.dumps({"count": len(pkgs), "packages": pkgs}, ensure_ascii=False, indent=2))
        else:
            print(f"User packages: {len(pkgs)}")
            for p in pkgs:
                print(p)

    # ---------- Inspect helpers ----------
    def get_pkg_paths(self, pkg: str) -> List[str]:
        cp = self.adb.shell("pm", "path", pkg, timeout=20)
        paths = []
        for line in cp.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                paths.append(line.split(":", 1)[1].strip())
        return paths

    def get_pkg_installer(self, pkg: str) -> Optional[str]:
        cp = self.adb.shell("pm", "list", "packages", "-i", pkg, timeout=20)
        txt = (cp.stdout + "\n" + cp.stderr).strip()
        m = re.search(rf"package:{re.escape(pkg)}(?:\s+installer=([^\s]+))?", txt)
        if m:
            return m.group(1) if m.group(1) else None
        cp2 = self.adb.shell("dumpsys", "package", pkg, timeout=30)
        m2 = re.search(r"installerPackageName=([^\s]+)", cp2.stdout + "\n" + cp2.stderr)
        if m2:
            return m2.group(1)
        return None

    def dumpsys_package(self, pkg: str) -> str:
        cp = self.adb.shell("dumpsys", "package", pkg, timeout=40)
        return (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")

    def appops_get(self, pkg: str) -> str:
        cp = self.adb.shell("cmd", "appops", "get", pkg, timeout=30)
        return (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")

    def query_launcher_presence(self, pkg: str) -> Optional[bool]:
        """
        True: ランチャーありと判断
        False: ランチャー無し/隠しの可能性が高い
        None: 不明（OS/機種差で判定不能）
        """
        # 1) resolve-activity --brief <pkg>
        try:
            cp = self.adb.shell("cmd", "package", "resolve-activity", "--brief", pkg, timeout=15)
            txt = (cp.stdout + "\n" + cp.stderr).strip()
            if cp.returncode == 0 and pkg in txt:
                return True
        except Exception:
            pass

        # 2) dumpsys で MAIN/LAUNCHER の痕跡を見る
        #    定義があるのに resolve できない場合は、無効化/隠しの可能性がある
        try:
            ds = self.dumpsys_package(pkg)
            has_main = "android.intent.action.MAIN" in ds
            has_launcher = "android.intent.category.LAUNCHER" in ds
            if has_main and has_launcher:
                return False
            return None
        except Exception:
            return None

    def parse_requested_permissions(self, dumpsys_txt: str) -> List[str]:
        perms = set()
        for line in dumpsys_txt.splitlines():
            if "permission." in line or line.strip().startswith("android.permission.") or line.strip().startswith("com.android."):
                m = re.findall(r"([A-Z_]{3,}|android\.permission\.[A-Z_]+)", line)
                for x in m:
                    if x.startswith("android.permission."):
                        perms.add(x.split(".")[-1])
                    elif x.isupper():
                        perms.add(x)
        if "BIND_ACCESSIBILITY_SERVICE" in dumpsys_txt:
            perms.add("BIND_ACCESSIBILITY_SERVICE")
        return sorted(perms)

    def parse_behavior_text_signals(self, dumpsys_txt: str) -> Dict[str, bool]:
        found: Dict[str, bool] = {}
        low = dumpsys_txt.lower()
        for key, (_label, _pts) in BEHAVIOR_TEXT_SIGNALS.items():
            found[key] = (key.lower() in low)
        return found

    def score_package(self, pkg: str, recent_count_10m: int = 0) -> ScoreResult:
        score = 0
        reasons: List[str] = []

        details: Dict[str, object] = {
            "pkg": pkg,
            "time": ts_iso(),
            "allowlisted": self.is_allowlisted(pkg),
            "recent_count_10m": recent_count_10m,
        }

        if self.is_allowlisted(pkg):
            return ScoreResult(pkg=pkg, score=0, reasons=["allowlisted"], details=details)

        # -------- 起動頻度シグナル（Displayedベース）--------
        if recent_count_10m >= 8:
            score += 30
            reasons.append(f"front-display頻度が高い ({recent_count_10m}/10min)")
        elif recent_count_10m >= 5:
            score += 20
            reasons.append(f"front-display頻度がやや高い ({recent_count_10m}/10min)")
        elif recent_count_10m >= 3:
            score += 10
            reasons.append(f"front-display頻度シグナル ({recent_count_10m}/10min)")

        # パッケージ名の弱いシグナル
        if SUSPICIOUS_NAME_RE.search(pkg):
            score += 5
            reasons.append("パッケージ名に広告/最適化系の弱いシグナル")

        installer = None
        paths: List[str] = []
        launcher_present: Optional[bool] = None
        dumpsys_txt = ""
        appops_txt = ""

        try:
            installer = self.get_pkg_installer(pkg)
        except Exception as ex:
            reasons.append(f"installer取得失敗: {ex}")

        try:
            paths = self.get_pkg_paths(pkg)
        except Exception as ex:
            reasons.append(f"path取得失敗: {ex}")

        try:
            launcher_present = self.query_launcher_presence(pkg)
        except Exception as ex:
            reasons.append(f"launcher判定失敗: {ex}")

        try:
            dumpsys_txt = self.dumpsys_package(pkg)
        except Exception as ex:
            reasons.append(f"dumpsys失敗: {ex}")

        try:
            appops_txt = self.appops_get(pkg)
        except Exception as ex:
            reasons.append(f"appops取得失敗: {ex}")

        details["installer"] = installer
        details["paths"] = paths
        details["launcher_present"] = launcher_present

        # -------- インストーラ元シグナル --------
        trusted_installers = {
            "com.android.vending",                  # Play Store
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.sec.android.app.samsungapps",      # Galaxy Store
            "com.huawei.appmarket",
            "com.xiaomi.market",
        }
        if installer is None:
            score += 10
            reasons.append("インストーラ不明")
        elif installer not in trusted_installers:
            score += 15
            reasons.append(f"非標準/未知のインストーラ: {installer}")

        # -------- APK配置位置（system領域なら自動削除は慎重に）--------
        if paths:
            if any(p.startswith("/data/app/") for p in paths):
                details["user_app_like"] = True
            if any("/system/" in p or "/product/" in p or "/vendor/" in p for p in paths):
                details["system_like"] = True
                score = max(0, score - 10)  # 慎重化（自動削除を避ける方向）
                reasons.append("システム領域アプリの可能性（自動削除は慎重）")

        # -------- dumpsys から権限シグナル --------
        requested_perms = self.parse_requested_permissions(dumpsys_txt) if dumpsys_txt else []
        details["requested_permissions"] = requested_perms
        for p in requested_perms:
            if p in PERM_SIGNALS:
                pts = PERM_SIGNALS[p]
                score += pts
                reasons.append(f"権限シグナル: {p} (+{pts})")

        # AccessibilityService 定義の痕跡（manifest保護以外でも出ることがある）
        if dumpsys_txt and "AccessibilityService" in dumpsys_txt and "BIND_ACCESSIBILITY_SERVICE" not in requested_perms:
            score += 15
            reasons.append("AccessibilityService 定義の痕跡 (+15)")

        # -------- appops から allow 状態 --------
        appops_found: List[str] = []
        for op, pts in APPOPS_SIGNALS.items():
            if re.search(rf"\b{re.escape(op)}\b\s*:\s*allow\b", appops_txt, flags=re.IGNORECASE):
                score += pts
                appops_found.append(op)
                reasons.append(f"AppOps許可: {op} (+{pts})")
        details["appops_allow_signals"] = appops_found

        # -------- dumpsys テキスト挙動シグナル（HiddenAds系向け）--------
        behavior_found: Dict[str, bool] = {}
        if dumpsys_txt:
            behavior_found = self.parse_behavior_text_signals(dumpsys_txt)
            details["behavior_text_signals"] = behavior_found
            for key, is_found in behavior_found.items():
                if is_found:
                    label, pts = BEHAVIOR_TEXT_SIGNALS[key]
                    score += pts
                    reasons.append(f"挙動シグナル: {label} (+{pts})")

        # -------- 複合ルール（相乗加点）--------
        has_overlay_perm = ("SYSTEM_ALERT_WINDOW" in requested_perms) or ("SYSTEM_ALERT_WINDOW" in appops_found)
        has_a11y = ("BIND_ACCESSIBILITY_SERVICE" in requested_perms) or (bool(dumpsys_txt) and "AccessibilityService" in dumpsys_txt)
        has_usage = ("PACKAGE_USAGE_STATS" in requested_perms) or ("GET_USAGE_STATS" in appops_found)
        boot_rx = bool(behavior_found.get("android.intent.action.BOOT_COMPLETED"))
        user_present_rx = bool(behavior_found.get("android.intent.action.USER_PRESENT"))

        # ランチャー無し/非通常 + 頻繁表示（HiddenAdsの典型寄り）
        if launcher_present is False and recent_count_10m >= 3:
            score += 15
            reasons.append("ランチャー無し/非通常 + 前面表示頻度 (HiddenAds系シグナル)")
        elif launcher_present is None and recent_count_10m >= 5:
            score += 8
            reasons.append("ランチャー不明 + 前面表示高頻度")

        # overlay + accessibility は非常に強い
        if has_overlay_perm and has_a11y:
            score += 30
            reasons.append("overlay + accessibility の組み合わせ (+30)")

        # overlay + usage stats（前景追跡+割り込み広告に使われやすい）
        if has_overlay_perm and has_usage:
            score += 15
            reasons.append("overlay + usage stats の組み合わせ (+15)")

        # USER_PRESENT + ランチャー非通常（アンロック契機 + 隠し）
        if user_present_rx and (launcher_present is False or launcher_present is None):
            score += 20
            reasons.append("USER_PRESENT監視 + ランチャー非通常 (HiddenAds疑い)")

        # BOOT_COMPLETED + overlay（再起動後継続）
        if boot_rx and has_overlay_perm:
            score += 12
            reasons.append("BOOT_COMPLETED + overlay (再起動後継続広告の疑い)")

        # 高頻度 + 非標準インストーラ + overlay
        if recent_count_10m >= 5 and has_overlay_perm and (installer not in trusted_installers):
            score += 15
            reasons.append("高頻度前面表示 + 非標準インストーラ + overlay")

        details["composite_flags"] = {
            "has_overlay_perm": has_overlay_perm,
            "has_a11y": has_a11y,
            "has_usage": has_usage,
            "boot_receiver": boot_rx,
            "user_present_receiver": user_present_rx,
        }

        # （任意）スコアの上限クリップ：暴走防止
        if score > 180:
            score = 180

        details["score"] = score
        return ScoreResult(pkg=pkg, score=score, reasons=reasons, details=details)

    def cmd_inspect(self, pkg: str, recent_window_sec: int = 600, json_out: bool = False):
        recent = self.count_recent(pkg, recent_window_sec)
        res = self.score_package(pkg, recent_count_10m=recent if recent_window_sec == 600 else recent)
        if json_out:
            print(json.dumps({
                "pkg": res.pkg,
                "score": res.score,
                "reasons": res.reasons,
                "details": res.details,
            }, ensure_ascii=False, indent=2))
            return

        print(f"Package : {res.pkg}")
        print(f"Score   : {res.score}")
        print("Reasons :")
        if res.reasons:
            for r in res.reasons:
                print(f"  - {r}")
        else:
            print("  (none)")
        print("Details :")
        for k, v in res.details.items():
            print(f"  {k}: {v}")

    # ---------- Actions ----------
    def force_stop(self, pkg: str, dry_run: bool = False):
        print(f"[ACTION] force-stop {pkg}" + (" (dry-run)" if dry_run else ""))
        if not dry_run:
            self.adb.shell("am", "force-stop", pkg, timeout=20)

    def disable_user(self, pkg: str, dry_run: bool = False):
        print(f"[ACTION] disable-user --user 0 {pkg}" + (" (dry-run)" if dry_run else ""))
        if not dry_run:
            self.adb.shell("pm", "disable-user", "--user", "0", pkg, timeout=20)

    def uninstall_user0(self, pkg: str, dry_run: bool = False):
        print(f"[ACTION] uninstall --user 0 {pkg}" + (" (dry-run)" if dry_run else ""))
        if not dry_run:
            self.adb.shell("pm", "uninstall", "--user", "0", pkg, timeout=30)

    def restore_pkg(self, pkg: str, dry_run: bool = False):
        print(f"[ACTION] enable --user 0 {pkg}" + (" (dry-run)" if dry_run else ""))
        if not dry_run:
            self.adb.shell("pm", "enable", "--user", "0", pkg, timeout=20)
        print(f"[ACTION] cmd package install-existing {pkg}" + (" (dry-run)" if dry_run else ""))
        if not dry_run:
            cp = self.adb.shell("cmd", "package", "install-existing", pkg, timeout=30)
            if cp.returncode != 0:
                eprint((cp.stdout + "\n" + cp.stderr).strip())

    def cmd_quarantine(self, pkg: str, dry_run: bool = False):
        self.force_stop(pkg, dry_run=dry_run)
        self.disable_user(pkg, dry_run=dry_run)

    def cmd_remove(self, pkg: str, dry_run: bool = False):
        self.force_stop(pkg, dry_run=dry_run)
        self.disable_user(pkg, dry_run=dry_run)
        self.uninstall_user0(pkg, dry_run=dry_run)

    def cmd_restore(self, pkg: str, dry_run: bool = False):
        self.restore_pkg(pkg, dry_run=dry_run)

    # ---------- Monitor / Auto ----------
    def count_recent(self, pkg: str, seconds: int = 600) -> int:
        dq = self.events_by_pkg.get(pkg, collections.deque())
        t = now_ts()
        return sum(1 for e in dq if (t - e.ts) <= seconds)

    def parse_displayed_line(self, line: str) -> Optional[Event]:
        m = DISPLAYED_RE.search(line)
        if not m:
            return None
        return Event(ts=now_ts(), pkg=m.group(1), activity=m.group(2), raw=line.rstrip())

    def stream_logcat(self, clear: bool = False):
        if clear:
            self.adb.run("logcat", "-c", timeout=10)

        cmd = self.adb._base_cmd() + ["logcat", "-s", "ActivityTaskManager", "ActivityManager"]
        eprint("[INFO] logcat stream start:", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                yield line
        finally:
            try:
                proc.kill()
            except Exception:
                pass

    def cmd_monitor(self, clear: bool = False, show_raw: bool = False):
        self.adb.ensure_device()
        for line in self.stream_logcat(clear=clear):
            evt = self.parse_displayed_line(line)
            if not evt:
                continue
            self.events_by_pkg[evt.pkg].append(evt)
            self.state.setdefault("last_seen", {})[evt.pkg] = evt.ts
            self.append_event_log(evt)
            self.save_state()

            recent = self.count_recent(evt.pkg, 600)
            print(f"[{ts_iso(evt.ts)}] {evt.pkg} {evt.activity}  (10m={recent})")
            if show_raw:
                print("  raw:", evt.raw)

    def apply_policy(
        self,
        res: ScoreResult,
        dry_run: bool = True,
        warn_threshold: int = DEFAULT_WARN_THRESHOLD,
        quar_threshold: int = DEFAULT_QUAR_THRESHOLD,
        remove_threshold: int = DEFAULT_REMOVE_THRESHOLD,
        aggressive_remove: bool = False,
    ):
        pkg = res.pkg
        actioned = self.state.setdefault("actioned", {})

        # 既に実行済みなら連打しない
        if pkg in actioned:
            print(f"[SKIP] {pkg} は既に actioned ({actioned[pkg]})")
            return

        print(f"[SCORE] {pkg} = {res.score}")
        for r in res.reasons:
            print(f"  - {r}")

        if res.score < warn_threshold:
            print("[POLICY] 記録のみ")
            return

        # 安全弁: system領域っぽいものは remove しない
        system_like = bool(res.details.get("system_like"))
        if system_like and res.score >= remove_threshold:
            print("[SAFETY] system_like のため REMOVE を抑止して QUARANTINE に格下げ")

        if res.score >= remove_threshold and aggressive_remove and not system_like:
            print("[POLICY] REMOVE")
            self.cmd_remove(pkg, dry_run=dry_run)
            actioned[pkg] = {
                "time": ts_iso(),
                "action": "remove" if not dry_run else "remove(dry-run)",
                "score": res.score,
                "reasons": res.reasons,
            }
            self.save_state()
            return

        if res.score >= quar_threshold:
            print("[POLICY] QUARANTINE")
            self.cmd_quarantine(pkg, dry_run=dry_run)
            actioned[pkg] = {
                "time": ts_iso(),
                "action": "quarantine" if not dry_run else "quarantine(dry-run)",
                "score": res.score,
                "reasons": res.reasons,
            }
            self.save_state()
            return

        print("[POLICY] force-stop only")
        self.force_stop(pkg, dry_run=dry_run)
        actioned[pkg] = {
            "time": ts_iso(),
            "action": "force-stop" if not dry_run else "force-stop(dry-run)",
            "score": res.score,
            "reasons": res.reasons,
        }
        self.save_state()

    def cmd_auto(
        self,
        clear: bool = False,
        dry_run: bool = True,
        min_count_for_inspect: int = 3,
        warn_threshold: int = DEFAULT_WARN_THRESHOLD,
        quar_threshold: int = DEFAULT_QUAR_THRESHOLD,
        remove_threshold: int = DEFAULT_REMOVE_THRESHOLD,
        aggressive_remove: bool = False,
        cool_down_sec: int = 600,
    ):
        self.adb.ensure_device()
        last_eval: Dict[str, float] = {}
        for line in self.stream_logcat(clear=clear):
            evt = self.parse_displayed_line(line)
            if not evt:
                continue

            self.events_by_pkg[evt.pkg].append(evt)
            self.state.setdefault("last_seen", {})[evt.pkg] = evt.ts
            self.append_event_log(evt)

            recent = self.count_recent(evt.pkg, 600)
            print(f"[{ts_iso(evt.ts)}] {evt.pkg} {evt.activity}  (10m={recent})")

            if self.is_allowlisted(evt.pkg):
                continue

            if recent < min_count_for_inspect:
                continue

            t = now_ts()
            if (t - last_eval.get(evt.pkg, 0)) < cool_down_sec:
                continue
            last_eval[evt.pkg] = t

            res = self.score_package(evt.pkg, recent_count_10m=recent)
            self.apply_policy(
                res,
                dry_run=dry_run,
                warn_threshold=warn_threshold,
                quar_threshold=quar_threshold,
                remove_threshold=remove_threshold,
                aggressive_remove=aggressive_remove,
            )
            self.save_state()


# =========================
# CLI
# =========================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description="ADB + logcat Displayed ベースの Android アドウェア調査/隔離ツール",
    )
    p.add_argument("--adb", default=ADB_BIN, help="adb 実行ファイル名/パス (default: adb)")
    p.add_argument("--serial", help="adb device serial (adb -s)")
    p.add_argument("--state-dir", help="状態保存ディレクトリ (default: %%USERPROFILE%%\\.adwscan)")
    p.add_argument("-v", "--verbose", action="store_true", help="adbコマンドを表示")

    sp = p.add_subparsers(dest="cmd", required=True)

    p_mon = sp.add_parser("monitor", help="Displayed イベント監視")
    p_mon.add_argument("--clear", action="store_true", help="開始前に logcat を clear")
    p_mon.add_argument("--show-raw", action="store_true", help="生ログも表示")

    p_inv = sp.add_parser("inventory", help="ユーザーアプリ一覧")
    p_inv.add_argument("--json", action="store_true", help="JSON出力")

    p_ins = sp.add_parser("inspect", help="パッケージ調査 + スコアリング")
    p_ins.add_argument("pkg", help="パッケージ名")
    p_ins.add_argument("--json", action="store_true", help="JSON出力")

    p_q = sp.add_parser("quarantine", help="force-stop + disable-user")
    p_q.add_argument("pkg")
    p_q.add_argument("--commit", action="store_true", help="実行する（無指定は dry-run）")

    p_rm = sp.add_parser("remove", help="force-stop + disable-user + uninstall --user 0")
    p_rm.add_argument("pkg")
    p_rm.add_argument("--commit", action="store_true", help="実行する（無指定は dry-run）")

    p_rs = sp.add_parser("restore", help="enable + install-existing")
    p_rs.add_argument("pkg")
    p_rs.add_argument("--commit", action="store_true", help="実行する（無指定は dry-run）")

    p_auto = sp.add_parser("auto", help="Displayed監視 + 自動スコアリング/対処")
    p_auto.add_argument("--clear", action="store_true", help="開始前に logcat を clear")
    p_auto.add_argument("--commit", action="store_true", help="実際に対処を実行（既定は dry-run）")
    p_auto.add_argument(
        "--aggressive-remove",
        action="store_true",
        help="remove 閾値超えで uninstall まで実行（既定は quarantine止まり）"
    )
    p_auto.add_argument(
        "--min-count",
        type=int,
        default=3,
        help="10分内の Displayed 回数がこの回数以上で inspect (default: 3)"
    )
    p_auto.add_argument("--warn-threshold", type=int, default=DEFAULT_WARN_THRESHOLD)
    p_auto.add_argument("--quarantine-threshold", type=int, default=DEFAULT_QUAR_THRESHOLD)
    p_auto.add_argument("--remove-threshold", type=int, default=DEFAULT_REMOVE_THRESHOLD)
    p_auto.add_argument(
        "--cool-down-sec",
        type=int,
        default=600,
        help="同一pkgを再評価するまでの最低秒数 (default: 600)"
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    adb = ADB(adb_bin=args.adb, serial=args.serial, verbose=args.verbose)
    state_dir = Path(args.state_dir) if args.state_dir else None
    tool = AdwScan(adb=adb, base_dir=state_dir)

    exit_code = 0
    try:
        if args.cmd == "monitor":
            tool.cmd_monitor(clear=args.clear, show_raw=args.show_raw)

        elif args.cmd == "inventory":
            adb.ensure_device()
            tool.cmd_inventory(json_out=args.json)

        elif args.cmd == "inspect":
            adb.ensure_device()
            tool.cmd_inspect(args.pkg, json_out=args.json)

        elif args.cmd == "quarantine":
            adb.ensure_device()
            tool.cmd_quarantine(args.pkg, dry_run=(not args.commit))

        elif args.cmd == "remove":
            adb.ensure_device()
            tool.cmd_remove(args.pkg, dry_run=(not args.commit))

        elif args.cmd == "restore":
            adb.ensure_device()
            tool.cmd_restore(args.pkg, dry_run=(not args.commit))

        elif args.cmd == "auto":
            tool.cmd_auto(
                clear=args.clear,
                dry_run=(not args.commit),
                min_count_for_inspect=args.min_count,
                warn_threshold=args.warn_threshold,
                quar_threshold=args.quarantine_threshold,
                remove_threshold=args.remove_threshold,
                aggressive_remove=args.aggressive_remove,
                cool_down_sec=args.cool_down_sec,
            )

        else:
            parser.print_help()
            exit_code = 2

    except KeyboardInterrupt:
        eprint("\n[INFO] interrupted")
        exit_code = 130
    except RuntimeError as ex:
        eprint(f"[ERROR] {ex}")
        exit_code = 1
    except subprocess.TimeoutExpired as ex:
        eprint(f"[ERROR] timeout: {ex}")
        exit_code = 1
    except FileNotFoundError:
        eprint("[ERROR] adb が見つかりません。Android SDK Platform-Tools の adb を PATH に通してください。")
        exit_code = 1
    finally:
        try:
            adb.kill_server()
            eprint("[INFO] adb server stopped")
        except Exception as ex:
            eprint(f"[WARN] adb server stop failed: {ex}")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
