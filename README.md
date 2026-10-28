# opencode-loomy-auth

把 **Loomy（讯飞）** 账号变成 magpie / OpenCode 的一个供应商：手机号 + 密码登录，拿 14 天 session，替 agent 发 OpenAI 兼容请求。

本包是 [loomy2api](https://github.com/Patrick130306/loomy2api) 的插件化移植：只保留账号服务签名、密码 RSA 加密、session 管理与模型网关请求头。HTTP 网关、账号池、失败切换、限流、面板、Anthropic 协议转换都由 magpie 自带，不再重复实现。

## 安装

```bash
magpie plugin add ./                 # 当前目录，本地开发
magpie plugin add opencode-loomy-auth  # 发布到 npm 之后

magpie plugin login loomy
magpie provider test loomy deepseek-v4-flash-0731
magpie quota
```

## 登录方式

| 方式 | 存什么 | 说明 |
|---|---|---|
| 自动导入 Loomy 桌面端登录态 | `key` = session | 读取本机 Loomy 客户端已登录的账号，无需短信；客户端重登后重新导入即可 |
| 手机号 + 短信验证码 | `key` = session（oauth） | 输入手机号后自动发码，再输 6 位验证码；不落密码 |
| Loomy 手机号 + 密码 | `key` = session，`metadata` = 手机号、密码、设备标识 | 会自动重登；密码以明文写进 magpie 的 `plugin-auth.json` |
| 粘贴已有 session | `key` = session | 不落密码，14 天后需重新粘贴 |

### session 从哪里来

1. **最简单：用手机号 + 密码**，插件登录后自动把 14 天 session 写进 magpie，不需要手动复制。
2. **桌面端已在用**：Loomy 是 Electron 应用，登录态以明文 JSON 存在 Chromium Local Storage 的 `loomy-auth-session` 键里：
   - Windows `%APPDATA%\Loomy\Local Storage\leveldb\*.log`
   - macOS `~/Library/Application Support/Loomy/Local Storage/leveldb/*.log`
   - Linux `~/.config/Loomy/Local Storage/leveldb/*.log`
   插件会自动读取并调 `/api/v1/models` 校验；也可用 `LOOMY_DESKTOP_DIR` 指定目录。magpie 跑在容器里时，需要把客户端的 `Local Storage/leveldb` 目录挂进容器并设 `LOOMY_DESKTOP_DIR`。
3. **不想给密码**：用短信验证码方式，登录后同样得到 14 天 session。
4. **已有 session**：直接粘贴；session 就是模型网关的 Bearer token。

想先看一眼桌面端的 session：

```bash
bun scripts/session.mjs
```

### 能不能走网页授权登录？

Loomy 没有 OAuth / 设备码授权接口。官方网页版 `https://loomy.xunfei.cn/web/` 用的是**另一套** `loomy_web_session` Cookie 和 `/web/api/...` 接口；桌面端插件用的是 `account.xfinfr.com` 登录换来的 session 和 `loomyad.xunfei.cn/api/v1`，两者不通用。所以无法一键“网页授权”后直接给本插件用；可行路径是上面的桌面端导入、短信或密码。

一个供应商可以登录多次，magpie 用 `metadata.email`（这里放手机号）区分账号，并把请求分给它们。多账号、故障切换、429 冷却都由 magpie 处理。

## 它做了什么

| 钩子 | 行为 |
|---|---|
| `config` | 注册供应商 `loomy`，`@ai-sdk/openai-compatible`，基址 `https://loomyad.xunfei.cn/api/v1`，附 11 个兜底模型 |
| `auth.methods` | 手机号 + 密码（`keyless` + `authorize` 内完成登录，不再要求 API key），或直接粘贴 session |
| `auth.loader` | 返回 `baseURL` 和 `fetch`；每个请求注入 `Authorization: Bearer`、`token`、`traceparent`、`loomy-version` |
| `auth.usage` | `GET /points/records` → 可用 / 余额 / 每日积分 |
| `provider.models` | `GET /models` 动态列表，失败时沿用内置清单 |
| 401 | 自动重登一次并重试，新 session 写回账号 |

session 有效期 14 天，没有 refresh token；magpie 的 `auth.refresh` 只续期 oauth 账号，所以本插件在 loader 发现 session 将过期、以及请求 401 时自行重登。通常不需要手动重新登录。

## 与 loomy2api 的对应

| loomy2api | 本插件 |
|---|---|
| `loomy2api/signer.py` | `lib/loomy.mjs` 的 `stringToSign` / `sign` / `buildAuthHeaders` |
| `loomy2api/crypto.py` | `lib/loomy.mjs` 的 `derToNumbers` / `rsaEncrypt`（纯 BigInt，无依赖） |
| `loomy2api/account.py` | `lib/loomy.mjs` 的 `login` / `loginWithSms` / `newIdentity`；`lib/desktop.mjs` 读桌面端 leveldb |
| `loomy2api/upstream.py` | `gatewayHeaders` / `fetchModels` / `fetchPoints` |
| `loomy2api/server.py` | magpie 网关（协议转换、流式、错误映射） |
| `loomy2api/pool.py` | magpie 多账号与故障切换 |
| `loomy2api/panel.py`、`cli.py` | magpie 自带 UI / CLI |

## 没包含

- **每日签到**：Loomy 侧没有可用的每日签到接口；`/points/first-login` 是首次登录奖励，不是签到，故不实现 `auth.checkin`。
- **Anthropic `/v1/messages`**：magpie 网关把 agent 的任意协议转成 chat completions，再交给本插件。
- **HTTP 代理**：插件使用宿主 fetch；需要代理时在 magpie 进程环境里配 `HTTPS_PROXY`。

## 测试

```bash
bun test
```

测试覆盖：签名黄金向量、RSA/PKCS#1 v1.5 与 Python 端口逐字节一致、登录请求形状、401 重登、模型映射、usage 映射。

在 magpie 沙箱里试（不碰自己的配置和登录）：

```bash
sb=$(mktemp -d)
m() { env HOME=$sb XDG_CONFIG_HOME=$sb/.config XDG_CACHE_HOME=$sb/.cache \
      MAGPIE_ADDR=127.0.0.1:3499 magpie "$@"; }
m plugin add ./
m plugin --json
m plugin login loomy
m provider test loomy deepseek-v4-flash-0731
m quota
```

## 发布

```bash
npm publish
```

`package.json` 的 `keywords` 已含 `opencode`、`opencode-plugin`、`loomy`。要进 magpie 的推荐列表，向社区仓库的 `registry.json` 加一项：

```json
{
  "package": "opencode-loomy-auth",
  "name": "Loomy",
  "providers": ["loomy"],
  "summary": {
    "en": "Loomy (iFlytek) coding plan through your phone number.",
    "zh": "用手机号登录 Loomy（讯飞）套餐。"
  }
}
```

## License

MIT，移植自 loomy2api（Copyright (c) 2026 loomy2api contributors）。
