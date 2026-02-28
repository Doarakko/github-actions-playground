---
on:
  schedule: daily around 9am utc+9
  workflow_dispatch:
permissions:
  contents: read
steps:
  - name: Install Trivy
    run: |
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  - name: Scan Node.js dependencies
    run: trivy fs --scanners vuln --format json --output /tmp/trivy-node.json functions/
  - name: Scan Python dependencies
    run: trivy fs --scanners vuln --format json --output /tmp/trivy-python.json poetry-project/
safe-outputs:
  create-pull-request:
    title-prefix: "[Security Fix] "
    labels: [security, automated, trivy]
    draft: true
    max: 1
    expires: 14
    fallback-as-issue: true
  create-issue:
    title-prefix: "[Trivy Report] "
    labels: [security, trivy-report]
    close-older-issues: true
    max: 1
---

## Trivy脆弱性の分析と自動修正

事前ステップで実行されたTrivyスキャン結果（/tmp/trivy-node.json, /tmp/trivy-python.json）を読み取り、脆弱性を修正する。

### 分析手順

1. /tmp/trivy-node.json と /tmp/trivy-python.json を読み取る
2. 脆弱性をCRITICAL/HIGH/MEDIUM/LOWに分類する
3. 脆弱性が0件なら何もしない（noop）

### 修正判断

- CRITICAL/HIGH: 自動修正PRを作成する
- MEDIUM: 修正可能なら自動修正、不可ならIssueで報告
- LOW: Issueでの報告のみ

### 自動修正の手順

#### Node.js (functions/)
1. 脆弱性のあるパッケージの修正バージョンをTrivy出力のFixedVersionから特定する
2. package.json のバージョンを更新する
3. `npm install` で package-lock.json を再生成する
4. `npm run lint` と `npm run build` で動作確認する

#### Python (poetry-project/)
1. 脆弱性のあるパッケージの修正バージョンをTrivy出力のFixedVersionから特定する
2. pyproject.toml のバージョン指定を更新する
3. `poetry lock` で poetry.lock を再生成する
4. `poetry export -f requirements.txt --output requirements.txt` で requirements.txt を更新する

### PR本文に含める情報
- 検出された脆弱性の一覧（CVE-ID、重要度、パッケージ名、修正バージョン）
- 各修正の説明
- 修正できなかった脆弱性があればその理由

### 修正不可の場合
- fallback-as-issue によりIssueとして脆弱性レポートを作成する
- 脆弱性の詳細、影響範囲、推奨対応を記載する

### 制約
- 破壊的変更（メジャーバージョンアップ）は避け、パッチ/マイナーアップデートのみ適用する
- ビルドやlintが通らない場合は修正を取り消し、Issueで報告する
