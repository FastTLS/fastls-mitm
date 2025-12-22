# GitHub Actions Workflows

## fastls-mitm 自动构建和发布

### 触发方式

#### 方式 1: 通过 Tag 触发（推荐）

推送以 `v` 开头的 tag 即可自动触发构建和发布：

```bash
# 创建并推送 tag
git tag v1.0.0
git push origin v1.0.0
```

#### 方式 2: 手动触发

1. 进入 GitHub 仓库的 Actions 页面
2. 选择 "Build and Release" workflow
3. 点击 "Run workflow"
4. 输入版本号（例如: 1.0.0）
5. 点击 "Run workflow" 按钮

### 支持的平台

- **Windows**: amd64, 386
- **Linux**: amd64, 386, arm64
- **macOS**: amd64, arm64

### 发布内容

每次发布会包含：
- 所有平台的可执行文件
- SHA256 校验文件
- Release 说明文档

### 版本信息

构建时会自动注入以下信息：
- 版本号（从 tag 或手动输入）
- 构建时间
- Git 提交 SHA

可通过 `fastls-mitm -version` 命令查看版本信息。

