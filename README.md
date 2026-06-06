# Cloud Notes

一个简单的客户端加密云便签。

- 前端：Vite + Vue 3 + TypeScript
- 后端：Node.js + TypeScript
- 加密：浏览器端 WebCrypto，PBKDF2 派生 AES-GCM 密钥
- 后端只保存密文，不接触密码和明文

## 本地开发

```bash
npm install
npm run dev -w backend
npm run dev -w frontend
```

默认端口：

- 前端：`5173`
- 后端：`1873`

## 构建

```bash
npm run build
```

## 生产运行

```bash
PORT=1873 \
DATA_FILE=/opt/cloud_notes/data/note.json \
PUBLIC_BASE_URL=http://47.92.254.25 \
NOTES_PATH=/notes/ \
GITHUB_CLIENT_ID=xxx \
GITHUB_CLIENT_SECRET=xxx \
GITHUB_ALLOWED_LOGINS=PANDAJSR \
npm run start -w backend
```

## GitHub OAuth

后端会先校验 GitHub 登录态，再允许读取或保存密文。

需要创建一个 GitHub OAuth App：

- Homepage URL: `http://47.92.254.25/notes/`
- Authorization callback URL: `http://47.92.254.25/api/auth/github/callback`

创建后把 Client ID、Client Secret 和允许访问的 GitHub 登录名配置到后端环境变量：

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_ALLOWED_LOGINS`
