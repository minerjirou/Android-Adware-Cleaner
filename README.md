# Android-Adware-Cleaner

Android で「見覚えのない広告が急に出る」「ホーム画面が勝手に切り替わる」といった症状を調べるための、
**ADB ベースの調査ツール**です。

このリポジトリの `adwscan.py` は、
**怪しいアプリを見つける → スコアで判断する → 段階的に止める** ところまでを支援します。
---
# 使う前の注意  
- このツールはモバイル端末に詳しい人の向けのソフトです。
- 作者環境下で実験を行っていません。
---

## まず何ができる？

- 端末で前面表示されたアプリを監視する（`monitor`）
- ユーザーアプリの一覧を出す（`inventory`）
- 指定アプリの危険度を採点する（`inspect`）
- 段階的に対処する
  - 一時停止 + 無効化（`quarantine`）
  - user 0 から削除（`remove`）
  - 復元（`restore`）
- 監視しながら自動判定する（`auto`、既定は dry-run）

---

## 3分で使う（最短手順）

### 1) 準備

- Python 3.10 以上
- `adb` が使える状態（Android SDK Platform-Tools）
- 端末で USB デバッグを有効化し、PC 接続を許可

確認:

```bash
adb devices
adb get-state
```

### 2) まずは状況確認

```bash
python3 adwscan.py inventory
python3 adwscan.py monitor
```

- `monitor` で短時間観察すると、頻繁に前面表示されるパッケージが見えてきます。

### 3) 怪しいパッケージを採点

```bash
python3 adwscan.py inspect com.example.suspicious
```

### 4) まずは安全側で対処（dry-run）

```bash
python3 adwscan.py quarantine com.example.suspicious
```

実際に実行する場合のみ `--commit` を付けます。

```bash
python3 adwscan.py quarantine com.example.suspicious --commit
```

---

## コマンド一覧（やさしめ説明）

### `monitor`
`logcat` の `Displayed` イベントを監視し、
「どのアプリが前面表示されたか」を記録します。

```bash
python3 adwscan.py monitor
python3 adwscan.py monitor --clear --show-raw
```

### `inventory`
ユーザーがインストールしたアプリ一覧を表示します。

```bash
python3 adwscan.py inventory
python3 adwscan.py inventory --json
```

### `inspect <pkg>`
指定パッケージの情報を集めてスコア化します。

```bash
python3 adwscan.py inspect com.example.suspicious
python3 adwscan.py inspect com.example.suspicious --json
```

### `quarantine <pkg>`
`force-stop` + `disable-user` を行います。

```bash
python3 adwscan.py quarantine com.example.suspicious
python3 adwscan.py quarantine com.example.suspicious --commit
```

### `remove <pkg>`
`quarantine` に加えて `uninstall --user 0` を実行します。

```bash
python3 adwscan.py remove com.example.suspicious
python3 adwscan.py remove com.example.suspicious --commit
```

### `restore <pkg>`
`enable` + `install-existing` で復元を試みます。

```bash
python3 adwscan.py restore com.example.suspicious
python3 adwscan.py restore com.example.suspicious --commit
```

### `auto`
監視しながら自動で採点し、ポリシーに沿って対処します。

```bash
# 既定は dry-run（安全）
python3 adwscan.py auto

# 実際に対処を実行
python3 adwscan.py auto --commit

# しきい値を調整
python3 adwscan.py auto --min-count 3 --warn-threshold 45 --quarantine-threshold 80 --remove-threshold 105

# remove まで許可（慎重に）
python3 adwscan.py auto --commit --aggressive-remove
```

---

## スコアは何を見ている？（ざっくり）

以下を組み合わせて危険度を計算します。

- 10分間で何回前面表示されたか
- パッケージ名の傾向（広告/最適化系ワード）
- インストーラ元が信頼できるか
- 権限/AppOps（overlay, accessibility など）
- `dumpsys package` 内の挙動シグナル（`BOOT_COMPLETED`, `USER_PRESENT` など）

> `system` 領域にあるアプリは、誤操作を避けるため自動削除を抑制します。

---

## 保存されるファイル

デフォルト保存先:

- Windows: `%USERPROFILE%\.adwscan`
- それ以外: `~/.adwscan`

中身:

- `allowlist.json` : 除外リスト
- `state.json` : 実行済みアクションや最終検知時刻
- `events.ndjson` : 監視イベントログ

保存先の変更:

```bash
python3 adwscan.py --state-dir /path/to/state auto
```

---

## 注意

- 既定は dry-run です。**まず dry-run で確認**してください。
- `remove --commit` は影響が大きいので、対象パッケージを十分確認してから実行してください。
- `uninstall --user 0` は端末全体の APK 完全削除とは異なります。

---
