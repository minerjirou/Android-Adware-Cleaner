# Android-Adware-Cleaner

`adwscan.py` は、ADB と logcat（`Displayed`）を使って Android 端末上の不審アプリを調査・対処する CLI ツールです。

## 機能

- `monitor`: `Displayed` イベント監視
- `inventory`: ユーザーアプリ一覧取得
- `inspect`: パッケージ調査とスコアリング
- `quarantine`: `force-stop` + `disable-user`
- `remove`: `force-stop` + `disable-user` + `uninstall --user 0`
- `restore`: `enable` + `install-existing`
- `auto`: 監視 + スコアリング + 段階的対処（既定は dry-run）

## 前提

- Python 3.10 以上
- Android SDK Platform-Tools（`adb`）
- 端末側で USB デバッグ有効化・接続許可

接続確認:

```bash
adb devices
adb get-state
```

## 基本的な使い方

ヘルプ:

```bash
python3 adwscan.py --help
```

一覧取得:

```bash
python3 adwscan.py inventory
python3 adwscan.py inventory --json
```

監視:

```bash
python3 adwscan.py monitor
python3 adwscan.py monitor --clear --show-raw
```

調査:

```bash
python3 adwscan.py inspect com.example.suspicious
python3 adwscan.py inspect com.example.suspicious --json
```

隔離/削除/復元:

```bash
python3 adwscan.py quarantine com.example.suspicious
python3 adwscan.py quarantine com.example.suspicious --commit

python3 adwscan.py remove com.example.suspicious
python3 adwscan.py remove com.example.suspicious --commit

python3 adwscan.py restore com.example.suspicious
python3 adwscan.py restore com.example.suspicious --commit
```

自動モード:

```bash
python3 adwscan.py auto
python3 adwscan.py auto --commit
python3 adwscan.py auto --min-count 3 --warn-threshold 45 --quarantine-threshold 80 --remove-threshold 105
python3 adwscan.py auto --commit --aggressive-remove
```

## 判定の主なシグナル

- 10分内の `Displayed` 回数
- パッケージ名パターン
- インストーラ情報
- APK 配置パス
- 権限/AppOps
- `dumpsys package` の挙動シグナル（`BOOT_COMPLETED` / `USER_PRESENT` など）

## 状態ファイル

デフォルト保存先:

- Windows: `%USERPROFILE%\.adwscan`
- それ以外: `~/.adwscan`

生成ファイル:

- `allowlist.json`
- `state.json`
- `events.ndjson`

保存先の変更:

```bash
python3 adwscan.py --state-dir /path/to/state auto
```

## 注意

- 既定は dry-run です。実行する場合のみ `--commit` を付けてください。
- `remove --commit` は影響が大きいため、対象パッケージを確認して実行してください。
- `uninstall --user 0` は端末全体からの完全削除ではありません。