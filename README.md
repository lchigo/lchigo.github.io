# lchigo.github.io

GitHub Pages 工具主页。

## 目录结构

```text
.
├── index.html
├── styles.css
├── theme.css              # 全站公共主题，在页面样式后加载
├── icons/                 # 统一的线条图标
└── tools/
    ├── comic-reader/
    ├── Lights-Out/
    ├── password-generator/
    ├── google-auth-2fa/
    └── image-steganography/
```

## UI 维护

公共颜色、字体、导航、容器宽度和控件规格集中在 `theme.css`；各工具的 `styles.css` 保留功能布局和专属状态样式。点灯棋盘保留黄色点亮状态，漫画阅读器保留全屏布局。

新增工具时，同时更新首页和 `tools/index.html` 的卡片列表与数量。公共主题和图标为本地静态资源，无外部依赖。

## 本地预览

在项目根目录启动任意静态文件服务器，然后访问首页。也可以直接打开 `index.html`。

## 发布

1. 在 GitHub 创建名为 `lchigo.github.io` 的公开仓库；
2. 将本地仓库推送到该仓库的 `main` 分支；
3. 在仓库 **Settings → Pages** 中确认发布源为 `main` 分支根目录；
4. 发布后访问 `https://lchigo.github.io/`。

漫画阅读器地址为 `https://lchigo.github.io/tools/comic-reader/`。
