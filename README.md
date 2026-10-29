# opencode-loomy-auth

把 **讯飞Loomy** 账号变成 magpie / OpenCode 的一个供应商：手机号+密码、手机号+短信、桌面端登录态导入或粘贴 session，拿到 14 天 session，替 agent 发 OpenAI 兼容请求。

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
| 自动导入 Loomy 桌面端登录态 | `type` = oauth，`access` = session | 读取本机 Loomy 客户端已登录的账号，无需短信；magpie 到期前通过 `auth.refresh` 重新读客户端登录态，客户端重登后自动换成新 session |
| 手机号 + 短信验证码 | `type` = oauth，`access` = session | 输入手机号后自动发码，再输 6 位验证码；不落密码，Loomy 无 refresh token。本机（或挂载进来的）桌面端登录同一手机号时，可借其 session 续期 |
| Loomy 手机号 + 密码 | `type` = api，`key` = session，`metadata` = 手机号、密码、设备标识 | 临近过期或请求 401/403 时自动重登；密码以明文写进 magpie 的 `plugin-auth.json` |
| 粘贴已有 session | `type` = api，`key` = session | 不落密码，14 天后需重新粘贴 |

### session 从哪里来

1. **最简单：用手机号 + 密码**，插件登录后自动把 14 天 session 写进 magpie，不需要手动复制。
2. **桌面端已在用**：Loomy 是 Electron 应用，登录态以明文 JSON 存在 Chromium Local Storage 的 `loomy-auth-session` 键里：
   - Windows `%APPDATA%\Loomy\Local Storage\leveldb\*.log`
   - macOS `~/Library/Application Support/Loomy/Local Storage/leveldb/*.log`
   - Linux `~/.config/Loomy/Local Storage/leveldb/*.log`
   插件会自动读取并调 `/api/v1/models` 校验；也可用 `LOOMY_DESKTOP_DIR` 指定目录。读到的登录态按 oauth 保存（`source` = `desktop`），到期前 magpie 会再读一次客户端登录态：只要客户端已经重新登录，就自动换上新的 session，不用重新导入。客户端登录态里若只有打码手机号（`maskedPhone`），插件不会把它当账号手机号，只保留 session 本身。magpie 跑在容器里时，需要把客户端的 `Local Storage/leveldb` 目录挂进容器并设 `LOOMY_DESKTOP_DIR`。
3. **不想给密码**：用短信验证码方式，登录后同样得到 14 天 session。
4. **已有 session**：直接粘贴；session 就是模型网关的 Bearer token。

想先看一眼桌面端的 session：

```bash
bun scripts/session.mjs
```

session 等同于账号凭据，勿外传。

### 能不能走网页授权登录？

Loomy 没有标准 OAuth / 设备码授权接口（本插件里的 `type` = oauth 只是 magpie 的账号存储类型，便于到期续期，不是 OAuth 协议）。官方网页版 `https://loomy.xunfei.cn/web/` 用的是**另一套** `loomy_web_session` Cookie 和 `/web/api/...` 接口；桌面端插件用的是 `account.xfinfr.com` 登录换来的 session 和 `loomyad.xunfei.cn/api/v1`，两者不通用。所以无法一键“网页授权”后直接给本插件用；可行路径是上面的桌面端导入、短信或密码。

一个供应商可以登录多次，magpie 用账号 id（oauth 的 `accountId`，api 的 `metadata.email`；这里都放手机号）区分账号，并把请求分给它们。多账号、故障切换、429 冷却都由 magpie 处理。

## 它做了什么

| 钩子 | 行为 |
|---|---|
| `config` | 注册供应商 `loomy`，`@ai-sdk/openai-compatible`，基址 `https://loomyad.xunfei.cn/api/v1`，附 11 个兜底模型 |
| `auth.methods` | 四种：桌面端自动导入（oauth）、手机号+短信验证码、手机号+密码（keyless + authorize），或直接粘贴 session |
| `auth.loader` | 返回 `baseURL` 和 `fetch`；每个请求注入 `Authorization: Bearer`、`token`、`traceparent`、`loomy-version`；没有密码可重登时，首次 401/403 的响应带 `X-Magpie-Sign-In: expired` |
| `auth.refresh` | 桌面端导入的 oauth 账号到期前重新读客户端登录态，客户端重登后返回新 session；其他账号返回 `undefined` |
| `auth.refreshLead` | 24 小时：magpie 在 session 到期前这么久开始尝试续期 |
| `auth.usage` | `GET /points/records`（v2，v1 回退）→ 钱包窗口：`balance` 可用积分、`resetsAt`/`span` 北京日 0 点重置、`runsOut` 当日会作废的每日积分；`plan` 取上游返回的套餐名 |
| `auth.checkin` | `POST /points/first-login` → 每日赠送积分刷新（按天幂等），回报 `until` = 北京日 0 点；已签到返回 `done` |
| `provider.models` | `GET /models` 动态列表，映射成宿主 GUI 形状（`capabilities`、`rate`/`free`），失败时沿用内置清单；session 失效错误码 `020002`/`100002` 会抛 `signIn: "expired"` |
| 401/403 | 有密码时自动重登一次并重试，新 session 写回账号；没有可用重登时标出需要重新登录 |

session 有效期 14 天，Loomy 没有 refresh token。桌面端导入按 oauth 保存并实现 `auth.refresh`：到期前重新读桌面端登录态，客户端重登过就自动续上。短信账号没有密码可重登，但若本机桌面端登录的是同一个手机号，`auth.refresh` 会借用桌面端的 session 续期；借不到就只能重新短信登录。粘贴的账号没有可续凭据，14 天后需重新粘贴。密码账号按 api 保存，在临近过期和请求 401/403 时用密码重登。没有密码可重登的账号，loader 会把首次 401/403 的响应加上 `X-Magpie-Sign-In: expired`，`provider.models` 遇到 session 失效错误码也会抛 `signIn: "expired"`，让 magpie 标记账号。通常不需要手动重新登录。

## 路由与配额

Loomy 的积分是**钱包**而不是百分比配额，所以 `auth.usage` 返回一个钱包窗口：

```json
{ "name": "积分", "balance": 120, "unit": "积分",
  "display": "可用 120（永久 100 + 每日 20）",
  "span": 86400, "resetsAt": "<下一个北京 0 点>",
  "runsOutAt": "<同上>", "runsOut": 20 }
```

magpie 的语义（见 `docs/reference.md`）：

- 只给 `display` 的窗口“没有份额”，路由会把这个账号当作**未知**，排在已知账号之后（这正是“基本不调度”的原因）。
- 给 `balance`（数字）+ `unit` 的窗口是钱包：路由知道这个账号，同一单位下余额多的优先。
- 给 `span` / `resetsAt` 后，Smart 路由会按“最快重置”排序：每日 0 点重置的 Loomy 比周窗口的渠道更早重置，于是**排在前面**（不用就作废）。
- 钱包余额为 0 时算作已用完。

若你的路由组用的是 `In order` 或手写权重，那套顺序优先于 Smart；要让它自动优先，用默认 **Smart**。

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

- **Anthropic `/v1/messages`**：magpie 网关把 agent 的任意协议转成 chat completions，再交给本插件。
- **HTTP 代理**：插件使用宿主 fetch；需要代理时在 magpie 进程环境里配 `HTTPS_PROXY`。

## 环境变量

| 变量 | 默认 | 用途 |
|---|---|---|
| `LOOMY_BASE_URL` | `https://loomyad.xunfei.cn/api/v1` | 模型网关（须以 `/api/v1` 结尾） |
| `LOOMY_ACCOUNT_BASE_URL` | `https://account.xfinfr.com` | 账号服务 |
| `LOOMY_DESKTOP_DIR` | 各平台默认 | 桌面端 `Local Storage/leveldb` 目录 |

## 测试

```bash
bun test
```

测试覆盖：签名黄金向量、RSA/PKCS#1 v1.5 与 Python 端口逐字节一致、登录请求形状、401/403 重登与过期标记、短信/桌面导入与 oauth 续期、两种模型形状与倍率、usage 与 checkin 映射、控制面超时。

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
  "name": "讯飞Loomy",
  "providers": ["loomy"],
  "summary": {
    "en": "Loomy (iFlytek) coding plan through your phone number.",
    "zh": "用手机号登录 Loomy（讯飞）套餐。"
  }
}
```

## 图标

供应商图标写在 `package.json` 的 `magpie.icon`（data URI，magpie 读一次即存本地，不依赖外链）：取自 Loomy 官网 `https://loomy.xunfei.cn/icon.png`，128×128、96 色量化后内嵌，约 4.8 KB。换图重跑：下载原图 → `resize((128,128), LANCZOS)` → `quantize(colors=96)` → base64。

## License

MIT，移植自 loomy2api（Copyright (c) 2026 loomy2api contributors）。
