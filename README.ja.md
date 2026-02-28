<p align="center">
  <a href="README.md">English</a> | <a href="README.zh.md">中文</a> | <a href="README.es.md">Español</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

Windows上で、「削除できない」ファイルを検出し、安全に削除するMCPサーバーです。

Windowsは、`CON`、`PRN`、`AUX`、`NUL`、`COM1`-`COM9`、および`LPT1`-`LPT9`などのデバイス名をWin32レイヤーで予約しています。これらの名前を持つファイルは、NTFS上で存在することがあります（WSL、Linuxツール、または低レベルAPIを使用して作成された場合）。しかし、これらのファイルは、エクスプローラーや通常のシェルコマンドを使用して、名前の変更、移動、または削除を行うことが不可能になります。

NullOutは、これらの危険なエントリを検出し、MCPホスト向けに設計された2段階の確認ワークフローを使用して、安全に削除します。この際、`\\?\`という拡張パス名前空間を使用します。

## 動作原理

1. **スキャン:** 許可リストに登録されたディレクトリをスキャンし、予約済みの名前との衝突、末尾のドット/スペース、および過度に長いパスを検出します。
2. **計画:** クリーンアップの計画を立てます。NullOutは、ファイルごとに確認用のトークンを生成し、ファイルID（ボリュームシリアル + ファイルID）にバインドします。
3. **削除:** トークンを使用して削除します。NullOutは、削除を実行する前に、ファイルが変更されていないことを再確認します（TOCTOU保護）。

## セキュリティモデル

- **許可リストに登録されたルートのみ:** 動作は、明示的に設定したディレクトリに限定されます。
- **破壊的な操作における生のパスの禁止:** 削除操作は、サーバーが発行したファイルIDと確認トークンのみを受け入れます。
- **deny_all再解析ポリシー:** ジャンクション、シンボリックリンク、およびマウントポイントは、一切トラバースまたは削除されません。
- **ファイルIDのバインド:** トークンはHMACで署名され、ボリュームシリアル + ファイルIDにバインドされます。スキャンと削除の間にファイルIDが変更された場合、操作は拒否されます。
- **空のディレクトリのみ:** バージョン1では、空でないディレクトリの削除は許可されません。
- **構造化されたエラー:** 失敗が発生した場合、機械可読なコードと、次のステップに関する提案が返されます。

## MCPツール

| ツール | タイプ | 目的 |
|------|------|---------|
| `list_allowed_roots` | 読み取り専用 | 設定されたスキャンルートを表示 |
| `scan_reserved_names` | 読み取り専用 | ルート内の危険なエントリを検出 |
| `get_finding` | 読み取り専用 | 特定のファイルの詳細情報を取得 |
| `plan_cleanup` | 読み取り専用 | 削除計画を生成し、確認トークンを付与 |
| `delete_entry` | 破壊的 | ファイルまたは空のディレクトリを削除（トークンが必要） |
| `who_is_using` | 読み取り専用 | ファイルをロックしているプロセスを特定（Restart Manager） |
| `get_server_info` | 読み取り専用 | サーバーのメタデータ、ポリシー、および機能 |

## 設定

許可リストに登録されたルートを環境変数で設定:

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

トークンの署名に使用する秘密鍵（ランダムな値を生成します）:

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## 脅威モデル

NullOutは、以下の脅威から保護します。

- **悪意のある使用:** 削除操作には、サーバーが発行した確認トークンが必要です。生のパスは受け付けられません。
- **パスのトラバーサル:** すべての操作は、許可リストに登録されたルートに限定されます。`..`によるパスの回避は解決され、拒否されます。
- **再解析ポイントの回避:** ジャンクション、シンボリックリンク、およびマウントポイントは、一切トラバースまたは削除されません（deny_all）。
- **TOCTOU競合:** トークンは、HMACでボリュームシリアル + ファイルIDにバインドされます。スキャンと削除の間にファイルIDが変更された場合、操作は拒否されます。
- **名前空間のトリック:** 破壊的な操作では、`\\?\`という拡張パスプレフィックスを使用して、Win32の名前解析を回避します。
- **ロックされたファイル:** Restart Managerによるプロセス属性の取得は、読み取り専用です。NullOutは、プロセスを強制終了することはありません。
- **空でないディレクトリ:** ポリシーによって拒否されます。削除できるのは、空のディレクトリのみです。

**アクセスされるデータ:** ファイルシステムのメタデータ（名前、ファイルID、ボリュームシリアル）、プロセスのメタデータ（PID、Restart Managerによるアプリケーション名）。
**アクセスされないデータ:** ファイルの内容、ネットワーク、認証情報、Windowsレジストリ。
**テレメトリは収集または送信されません。**

## システム要件

- Windows 10/11
- Python 3.10+

---

開発者: <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a>
