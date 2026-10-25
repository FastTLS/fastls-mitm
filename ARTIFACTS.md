# 开发产物与来源证明

## 范围

`Development artifacts` 只生成临时开发构建。它在 `main` 更新或手动触发时运行，不创建 tag、GitHub Release 或正式版本；Actions 产物保留 14 天。

工作流为 Linux、Windows、macOS 的 amd64/arm64 生成归档。归档名包含 `dev-<commit前12位>`，内部包含 `fastls-mitm`（Windows 为 `.exe`）和 `BUILD_INFO.txt`。归档不包含 CA 证书或私钥；首次运行时程序会按配置创建它们。

## 下载

从 Actions 页面下载 `fastls-mitm-development-<完整提交SHA>`，或使用：

```bash
gh run list --repo FastTLS/fastls-mitm --workflow development-artifacts.yml
gh run download RUN_ID \
  --repo FastTLS/fastls-mitm \
  --name fastls-mitm-development-COMMIT_SHA \
  --dir fastls-mitm-artifacts
```

下载目录包含六个平台归档、`SHA256SUMS` 和 `provenance.sigstore.json`。

## 校验摘要

```bash
cd fastls-mitm-artifacts
sha256sum --check SHA256SUMS
```

macOS 可用 `shasum -a 256`，PowerShell 可用 `Get-FileHash -Algorithm SHA256` 逐项对照。

## 验证签发来源

在线验证：

```bash
gh attestation verify fastls-mitm-dev-COMMIT-linux-amd64.tar.gz \
  --repo FastTLS/fastls-mitm \
  --signer-workflow FastTLS/fastls-mitm/.github/workflows/development-artifacts.yml
```

使用随包证明：

```bash
gh attestation verify fastls-mitm-dev-COMMIT-linux-amd64.tar.gz \
  --repo FastTLS/fastls-mitm \
  --bundle provenance.sigstore.json \
  --signer-workflow FastTLS/fastls-mitm/.github/workflows/development-artifacts.yml
```

完全离线验证还需在联网环境准备 `gh attestation trusted-root > trusted_root.jsonl`，离线命令额外传入 `--custom-trusted-root trusted_root.jsonl`。

验证成功表示归档摘要与签发工作流身份匹配，不表示该构建是正式版本，也不代表运行 MITM 代理已获得流量所有者授权。

## 签发链路

工作流先验证 module、测试和静态检查，再用 `CGO_ENABLED=0`、`-trimpath` 和嵌入的提交信息交叉构建。随后计算 SHA-256，通过 GitHub OIDC/Sigstore 生成 SLSA provenance，并用限定仓库及签发工作流的策略自验证后上传。
