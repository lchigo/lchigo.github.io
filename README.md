# lchigo.github.io

GitHub Pages 工具主页。

## 目录结构

```text
.
├── index.html
├── styles.css
├── theme.css              # 全站公共设计系统（浅色），在页面样式之前加载
├── icons/                 # 统一的线条图标
└── tools/
    ├── comic-reader/
    ├── Lights-Out/
    ├── password-generator/
    ├── google-auth-2fa/
    └── image-steganography/
```

## UI 维护

全站使用统一的浅色主题：点阵纸底色 + 白色工作面板，松绿色 `--accent` 负责所有主要操作和“安全 / 完成”状态，等宽字体只用于密码、验证码、密钥和数字。

- `theme.css`：设计令牌（颜色、字体、圆角、阴影）和公共组件——页头导航、工具页标题区、`.panel`、输入框、状态提示（`status-info / success / warning / error`）、页脚。每个页面**先**加载它。
- 各工具的 `styles.css`：只保留该工具的布局和专属组件，颜色一律引用 `theme.css` 中的变量，不再写死色值。
- 例外：点灯棋盘的点亮格使用 `--lamp` 黄色；漫画阅读器保持全屏布局。

新增工具时，复用 `topbar / hero / panel` 结构并引用设计令牌，同时更新首页和 `tools/index.html` 的卡片列表与数量。公共主题和图标为本地静态资源，无外部依赖（2FA 与隐写工具的 CSP 禁止外部字体和内联样式）。

## 本地预览

在项目根目录启动任意静态文件服务器，然后访问首页。也可以直接打开 `index.html`。

## 发布

1. 在 GitHub 创建名为 `lchigo.github.io` 的公开仓库；
2. 将本地仓库推送到该仓库的 `main` 分支；
3. 在仓库 **Settings → Pages** 中确认发布源为 `main` 分支根目录；
4. 发布后访问 `https://lchigo.github.io/`。

漫画阅读器地址为 `https://lchigo.github.io/tools/comic-reader/`。
