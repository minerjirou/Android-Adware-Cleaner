# Android-Adware-Cleaner

`adwscan.py` は、**ADB と logcat の `Displayed` イベント**を使って、
Android 端末上の不審アプリ（特に HiddenAds 系を想定）を調査・隔離・削除支援する CLI ツールです。

> ⚠️ このツールは端末のアプリ状態を変更できます。実行前に必ず内容を確認し、自己責任で使用してください。

---

## できること

- `monitor` : `Displayed` イベントを監視して、前面表示されたアプリを記録
- `inventory` : ユーザーアプリ一覧を取得
- `inspect` : 指定パッケージを調査してスコアリング
- `quarantine` : `force-stop` + `disable-user`
- `remove` : `force-stop` + `disable-user` + `uninstall --user 0`
- `restore` : `enable` + `install-existing`
- `auto` : 監視しながらスコアリングし、ポリシーに従って段階的対処（既定は dry-run）

---

## 前提条件

- Python 3.10 以上（目安）
- Android SDK Platform-Tools (`adb`) がインストール済みで、PATH が通っている
- 端末側で USB デバッグ有効化・接続許可済み

接続確認例:

```bash
adb devices
adb get-state
```

---

## 使い方

### 1. ヘルプ

```bash
python3 adwscan.py --help
```

### 2. ユーザーアプリ一覧

```bash
python3 adwscan.py inventory
python3 adwscan.py inventory --json
```

### 3. 監視（Displayed イベント）

```bash
python3 adwscan.py monitor
python3 adwscan.py monitor --clear --show-raw
```

### 4. 単体調査（スコア確認）

```bash
python3 adwscan.py inspect com.example.suspicious
python3 adwscan.py inspect com.example.suspicious --json
```

### 5. 隔離・削除・復元

デフォルトは **dry-run（実行しない）** です。実行する場合は `--commit` を付けます。

```bash
# 隔離
python3 adwscan.py quarantine com.example.suspicious
python3 adwscan.py quarantine com.example.suspicious --commit

# 削除（user 0）
python3 adwscan.py remove com.example.suspicious
python3 adwscan.py remove com.example.suspicious --commit

# 復元
python3 adwscan.py restore com.example.suspicious
python3 adwscan.py restore com.example.suspicious --commit
```

### 6. 自動モード

```bash
# 既定は dry-run
python3 adwscan.py auto

# 実際に対処を実行
python3 adwscan.py auto --commit

# しきい値や評価条件を調整
python3 adwscan.py auto --min-count 3 --warn-threshold 45 --quarantine-threshold 80 --remove-threshold 105

# remove まで許可（高リスク）
python3 adwscan.py auto --commit --aggressive-remove
```

---

## スコアリングの概要

主に以下のシグナルを合算します。

- `Displayed` の頻度（10分内）
- パッケージ名の弱い疑わしさ
- インストーラ元（Play Store 等かどうか）
- APK パス（system 領域かどうか）
- 危険寄り権限・AppOps 状態
- `dumpsys package` 内の挙動テキスト（`BOOT_COMPLETED`, `USER_PRESENT` など）
- 複合条件（例: overlay + accessibility）

`system` 領域由来っぽいアプリは、削除を自動で抑制する安全弁が入っています。

---

## 保存される状態ファイル

デフォルト保存先:

- Windows: `%USERPROFILE%\.adwscan`
- それ以外: `~/.adwscan`

主なファイル:

- `allowlist.json` : 許可リスト（除外対象）
- `state.json` : 最終検知時刻や action 済み記録
- `events.ndjson` : 監視イベントログ

保存先を変える場合:

```bash
python3 adwscan.py --state-dir /path/to/state auto
```

---

## 注意事項

- 誤検知の可能性があります。特に `remove --commit` は慎重に。
- `uninstall --user 0` は「ユーザー 0 からのアンインストール」であり、端末全体から APK を完全削除する動作ではありません。
- 端末や OS 差分により、`dumpsys` / `appops` の出力形式が異なる場合があります。

---

## ライセンス

必要に応じて本リポジトリの方針に合わせて追記してください。
