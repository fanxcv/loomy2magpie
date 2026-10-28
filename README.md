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
| Loomy 手机号 + 密码 | `key` = session，`metadata` = 手机号、密码、设备标识 | 会自动重登；密码以明文写进 magpie 的 `plugin-auth.json` |
| 粘贴已有 session | `key` = session | 不落密码，14 天后需重新粘贴 |

一个供应商可以登录多次，magpie 用 `accountId`（手机号）区分账号，并把请求分给它们。多账号、故障切换、429 冷却都由 magpie 处理。

## 它做了什么

| 钩子 | 行为 |
|---|---|
| `config` | 注册供应商 `loomy`，`@ai-sdk/openai-compatible`，基址 `https://loomyad.xunfei.cn/api/v1`，附 11 个兜底模型 |
| `auth.methods` | 手机号 + 密码（`authorize` 内完成登录），或直接粘贴 session |
| `auth.loader` | 返回 `baseURL` 和 `fetch`；每个请求注入 `Authorization: Bearer`、`token`、`traceparent`、`loomy-version` |
| `auth.refresh` | 到期前 24 小时用保存的手机号/密码重新登录（宿主支持时） |
| `auth.usage` | `GET /points/records` → 可用 / 余额 / 每日积分 |
| `provider.models` | `GET /models` 动态列表，失败时沿用内置清单 |
| 401 | 自动重登一次并重试，新 session 写回账号 |

session 有效期 14 天，没有 refresh token。插件在 loader 和请求 401 时都会自愈，所以通常不需要手动重新登录。

## 与 loomy2api 的对应

| loomy2api | 本插件 |
|---|---|
| `loomy2api/signer.py` | `lib/loomy.mjs` 的 `stringToSign` / `sign` / `buildAuthHeaders` |
| `loomy2api/crypto.py` | `lib/loomy.mjs` 的 `derToNumbers` / `rsaEncrypt`（纯 BigInt，无依赖） |
| `loomy2api/account.py` | `lib/loomy.mjs` 的 `login` / `newIdentity` |
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
