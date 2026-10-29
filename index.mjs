// magpie / OpenCode 供应商插件入口。
// 只导出插件函数；辅助函数都在 lib/ 下，避免被宿主当成插件执行。

import {
  BASE,
  PROVIDER,
  SESSION_TTL,
  fetchModels,
  fetchPoints,
  gatewayHeaders,
  login,
  loginWithSms,
  newIdentity,
  sendSmsCode,
} from "./lib/loomy.mjs";
import { readDesktopSession } from "./lib/desktop.mjs";
import { FALLBACK_MODELS, mergeModels, toConfigModels } from "./lib/models.mjs";

const REFRESH_LEAD = 24 * 3600 * 1000;

const metaOf = (auth) => {
  const meta = auth?.metadata && typeof auth.metadata === "object" ? auth.metadata : {};
  return auth?.phone ? { ...meta, phone: auth.phone } : meta;
};
const keyOf = (auth) =>
  typeof auth?.key === "string" ? auth.key : typeof auth?.access === "string" ? auth.access : "";
const stale = (auth) => {
  if (typeof auth?.expires === "number" && auth.expires > 0) {
    return Date.now() > auth.expires - REFRESH_LEAD;
  }
  const meta = metaOf(auth);
  return !meta.obtainedAt || Date.now() - Number(meta.obtainedAt) > SESSION_TTL - REFRESH_LEAD;
};

async function sessionFor(auth) {
  const session = keyOf(auth);
  const meta = metaOf(auth);
  if (session && !stale(auth)) return session;
  if (meta.phone && meta.password) {
    return (await login(meta.phone, meta.password, meta.identity)).session;
  }
  return session;
}

const DAILY_SPAN = 86400;

const numOf = (value) => {
  const n = typeof value === "string" ? Number(value.trim()) : Number(value);
  return Number.isFinite(n) ? n : 0;
};

// 与 numOf 不同：缺失/非数字返回 undefined，好让合法的 0 不被 `||` 吞掉。
const maybeNum = (value) => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "string" && value.trim() === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
};

const signInExpired = (code) => code === "020002" || code === "100002";

// Loomy 的每日赠送积分按北京日 0 点重置；magpie 的 Smart 路由按“最快重置”优先。
function nextDailyReset(now = Date.now()) {
  const CST = 8 * 3600 * 1000;
  const dayStart = Math.floor((now + CST) / 86400000) * 86400000;
  return dayStart + 86400000 - CST;
}

export const LoomyAuthPlugin = async ({ client } = {}) => {
  const log = (level, message) => {
    try {
      client?.app?.log?.({ body: { service: "loomy", level, message } });
    } catch {
      // 日志失败不影响请求
    }
  };

  const save = async (auth, got, meta) => {
    const body =
      auth?.type === "oauth"
        ? { ...auth, access: got.session, expires: Date.now() + SESSION_TTL }
        : {
            ...(auth && typeof auth === "object" ? auth : {}),
            type: "api",
            key: got.session,
            metadata: {
              ...meta,
              userId: got.userid || meta.userId,
              identity: got.identity || meta.identity,
              obtainedAt: Date.now(),
            },
          };
    try {
      await client?.auth?.set?.({ path: { id: PROVIDER }, body });
    } catch (error) {
      log("warn", `保存 session 失败：${error.message}`);
    }
  };

  return {
    config: async (cfg) => {
      cfg.provider ??= {};
      cfg.provider[PROVIDER] ??= {
        name: "讯飞Loomy",
        npm: "@ai-sdk/openai-compatible",
        api: BASE,
        models: toConfigModels(FALLBACK_MODELS),
      };
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD,

      // 桌面端登录态是 oauth：到期前重新读 leveldb，客户端重登后自动换上
      // 新 session；短信/粘贴的账号没有 refresh token，只有本机桌面端登录的
      // 是同一个手机号时才能借它的 session 续期。
      async refresh(auth) {
        const found = readDesktopSession();
        if (!found?.session || found.session === auth?.access) return undefined;
        const mine = String(auth?.accountId || auth?.phone || "").trim();
        const theirs = String(found.phone || "").trim();
        if (auth?.source !== "desktop" && (!mine || mine !== theirs)) return undefined;
        return {
          access: found.session,
          refresh: "",
          expires: (Number(found.loggedInAt) || Date.now()) + SESSION_TTL,
          phone: found.phone || "",
          userId: found.userid || "",
          obtainedAt: Date.now(),
        };
      },

      methods: [
        {
          type: "api",
          label: "自动导入 Loomy 桌面端登录态",
          keyless: true,
          async authorize() {
            const found = readDesktopSession();
            if (!found) {
              return {
                type: "failed",
                error: "未找到本机 Loomy 桌面端登录态；请先在 Loomy 客户端登录，或改用短信/密码/粘贴 session",
              };
            }
            try {
              await fetchModels(found.session);
            } catch (error) {
              return {
                type: "failed",
                error: `桌面端 session 校验失败（可能已过期或网络不通）：${error.message}`,
              };
            }
            return {
              type: "success",
              access: found.session,
              // host 的 save() 以 "refresh" in result 判定 oauth，空串也算。
              refresh: "",
              expires: (Number(found.loggedInAt) || Date.now()) + SESSION_TTL,
              source: "desktop",
              accountId: found.phone || undefined,
              phone: found.phone || "",
              userId: found.userid || "",
              obtainedAt: Date.now(),
            };
          },
        },
        {
          type: "oauth",
          label: "手机号 + 短信验证码",
          prompts: [
            {
              type: "text",
              key: "phone",
              message: "Loomy 手机号",
              placeholder: "13800138000",
              validate: (v) => (String(v || "").trim() ? undefined : "请输入手机号"),
            },
          ],
          async authorize(inputs) {
            const phone = String(inputs?.phone || "").trim();
            if (!phone) return { type: "failed", error: "请输入手机号" };
            let sent;
            try {
              sent = await sendSmsCode(phone);
            } catch (error) {
              return { type: "failed", error: String(error.message || error).slice(0, 500) };
            }
            const msgid = sent?.data?.msgid || sent?.msgid || "";
            if (!msgid) return { type: "failed", error: "发送验证码失败：上游未返回 msgid" };
            return {
              url: "",
              instructions: `验证码已发到 ${phone}，请输入 6 位短信验证码`,
              method: "code",
              async callback(code) {
                try {
                  const got = await loginWithSms(phone, String(code || "").trim(), msgid, newIdentity());
                  return {
                    type: "success",
                    access: got.session,
                    refresh: "",
                    expires: Date.now() + SESSION_TTL,
                    accountId: got.phone || phone,
                    uid: got.userid || undefined,
                    phone,
                  };
                } catch (error) {
                  return { type: "failed", error: String(error.message || error).slice(0, 500) };
                }
              },
            };
          },
        },
        {
          type: "api",
          label: "Loomy 手机号 + 密码",
          placeholder: "13800138000",
          keyless: true,
          prompts: [
            {
              type: "text",
              key: "phone",
              message: "Loomy 手机号",
              placeholder: "13800138000",
              validate: (v) => (String(v || "").trim() ? undefined : "请输入手机号"),
            },
            {
              type: "password",
              key: "password",
              message: "Loomy 密码",
              validate: (v) => (String(v || "") ? undefined : "请输入密码"),
            },
          ],
          async authorize(inputs) {
            const phone = String(inputs?.phone || "").trim();
            const password = String(inputs?.password || "");
            if (!phone || !password) return { type: "failed", error: "手机号和密码都要填" };
            try {
              const got = await login(phone, password, newIdentity());
              return {
                type: "success",
                key: got.session,
                metadata: {
                  email: got.phone || phone,
                  phone,
                  password,
                  userId: got.userid,
                  identity: got.identity,
                  obtainedAt: Date.now(),
                },
              };
            } catch (error) {
              return { type: "failed", error: String(error.message || error).slice(0, 500) };
            }
          },
        },
        {
          type: "api",
          label: "粘贴已有 session（不存密码）",
          placeholder: "14 天 session token",
        },
      ],

      async loader(getAuth) {
        const auth = await getAuth();
        const meta = metaOf(auth);
        const state = {
          auth,
          session: keyOf(auth),
          retried: false,
          pending: null,
        };

        const relogin = () => {
          if (!meta.phone || !meta.password) return Promise.resolve(state.session);
          state.pending ??= login(meta.phone, meta.password, meta.identity)
            .then(async (got) => {
              state.session = got.session;
              await save(auth, got, meta);
              return state.session;
            })
            .finally(() => {
              state.pending = null;
            });
          return state.pending;
        };

        if (meta.phone && meta.password && (!state.session || stale(auth))) {
          try {
            await relogin();
          } catch (error) {
            log("warn", `重新登录失败：${error.message}`);
          }
        }

        if (!state.session) return {};

        const send = (input, init, session) => {
          const headers = new Headers(init?.headers);
          for (const [key, value] of Object.entries(gatewayHeaders(session))) {
            headers.set(key, value);
          }
          return fetch(input, { ...init, headers });
        };

        // 没有密码可重登（或重登失败）时告诉宿主这账号需要重新登录；
        // body 保持原流，不在这里读走。
        const expired = (response) => {
          const headers = new Headers(response.headers);
          headers.set("X-Magpie-Sign-In", "expired");
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers,
          });
        };

        return {
          baseURL: BASE,
          apiKey: state.session,
          headers: gatewayHeaders(state.session),
          async fetch(input, init) {
            let response = await send(input, init, state.session);
            if ((response.status === 401 || response.status === 403) && !state.retried) {
              if (!meta.phone || !meta.password) return expired(response);
              state.retried = true;
              try {
                const session = await relogin();
                response = await send(input, init, session);
              } catch (error) {
                log("warn", `session 失效后重登失败：${error.message}`);
                return expired(response);
              }
            }
            return response;
          },
        };
      },
      async usage(getAuth) {
        const auth = await getAuth();
        const meta = metaOf(auth);
        try {
          const session = await sessionFor(auth);
          if (!session) return { error: "账号没有可用 session", windows: [] };
          const payload = await fetchPoints(session);
          const code = String(payload?.code ?? payload?.errorCode ?? "");
          if (code && code !== "000000" && code !== "0") {
            const gone = signInExpired(code);
            return {
              error: payload?.desc || payload?.message || `积分查询失败 (${code})`,
              windows: [],
              ...(gone ? { signIn: "expired" } : {}),
            };
          }
          // 摘要在 data 或 data.data 两层（不同版本两种形态）
          const data = payload?.data?.data ?? payload?.data ?? {};
          const permanent = numOf(data.balance);
          const daily = numOf(data.dailyBalance);
          const available = maybeNum(data.availableBalance) ?? permanent + daily;
          const reset = new Date(nextDailyReset()).toISOString();
          return {
            plan: data.planName || data.plan || data.vipName || "",
            user: meta.phone || auth?.accountId || "",
            balance: `${available} 积分`,
            // 钱包读数：路由知道这个账号，余额越多越先；span/resetsAt 让 Smart 按
            // “最快重置”优先（每日赠送积分 0 点重置，不用就作废）。
            windows: [
              {
                name: "积分",
                balance: available,
                unit: "积分",
                display: `可用 ${available}（永久 ${permanent} + 每日 ${daily}）`,
                span: DAILY_SPAN,
                resetsAt: reset,
                runsOutAt: reset,
                runsOut: daily,
              },
            ],
          };
        } catch (error) {
          return { error: `额度查询失败：${error.message}`, windows: [] };
        }
      },

      async checkin(getAuth) {
        const auth = await getAuth();
        try {
          const session = await sessionFor(auth);
          if (!session) return { outcome: "failed", message: "账号没有可用 session" };
          const res = await fetch(`${BASE}/points/first-login`, {
            method: "POST",
            headers: gatewayHeaders(session),
            body: "{}",
            signal: AbortSignal.timeout(20_000),
          });
          const payload = await res.json().catch(() => null);
          const code = payload?.code ?? payload?.errorCode;
          const message = payload?.desc || payload?.message || `HTTP ${res.status}`;
          const until = new Date(nextDailyReset()).toISOString();
          const ok = res.ok && (!code || code === "000000" || code === 0 || code === "0");
          if (!ok) {
            if (/已签到|重复|already|repeat/i.test(message)) {
              return { outcome: "done", message, until };
            }
            return { outcome: "failed", message };
          }
          // until 告诉 magpie 何时再来问：北京日 0 点，与 usage 的重置窗口一致。
          // 不给 until 时，magpie 当天失败后不再重试，签到页会一直挂着旧结果。
          return {
            outcome: "claimed",
            message: "每日赠送积分已刷新",
            until,
          };
        } catch (error) {
          return { outcome: "failed", message: String(error.message || error) };
        }
      },
    },

    provider: {
      id: PROVIDER,
      async models(provider, { auth } = {}) {
        const base = provider?.models || {};
        let session = "";
        try {
          session = await sessionFor(auth);
        } catch {
          session = keyOf(auth);
        }
        if (!session) return base;
        try {
          const payload = await fetchModels(session);
          const code = String(payload?.code ?? payload?.errorCode ?? "");
          if (signInExpired(code)) {
            const error = new Error(payload?.desc || payload?.message || `session 失效 (${code})`);
            error.signIn = "expired";
            throw error;
          }
          return mergeModels(base, payload.data || payload.models || []);
        } catch (error) {
          if (error.signIn === "expired") throw error;
          log("warn", `拉取模型列表失败，沿用内置清单：${error.message}`);
          return base;
        }
      },
    },
  };
};
