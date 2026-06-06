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
PORT=1873 DATA_FILE=/opt/cloud_notes/data/note.json npm run start -w backend
```
