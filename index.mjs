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
  newIdentity,
} from "./lib/loomy.mjs";
import { FALLBACK_MODELS, mergeModels, toConfigModels } from "./lib/models.mjs";

const VERSION = "0.1.0";
const REFRESH_LEAD = 24 * 3600 * 1000;

const metaOf = (auth) =>
  auth?.metadata && typeof auth.metadata === "object" ? auth.metadata : {};
const keyOf = (auth) => (typeof auth?.key === "string" ? auth.key : "");
const stale = (meta) =>
  !meta.obtainedAt || Date.now() - Number(meta.obtainedAt) > SESSION_TTL - REFRESH_LEAD;

async function sessionFor(auth) {
  const key = keyOf(auth);
  const meta = metaOf(auth);
  if (key && !stale(meta)) return key;
  if (meta.phone && meta.password) {
    return (await login(meta.phone, meta.password, meta.identity)).session;
  }
  return key;
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
    const body = {
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
      cfg.provider[PROVIDER] = {
        name: "Loomy（讯飞）",
        npm: "@ai-sdk/openai-compatible",
        api: BASE,
        models: toConfigModels(FALLBACK_MODELS),
        ...(cfg.provider[PROVIDER] || {}),
      };
    },

    auth: {
      provider: PROVIDER,
      refreshLead: REFRESH_LEAD,

      methods: [
        {
          type: "api",
          label: "Loomy 手机号 + 密码",
          placeholder: "13800138000",
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
                accountId: got.phone || phone,
                uid: got.userid || undefined,
                expires: Date.now() + SESSION_TTL,
                metadata: {
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
          meta,
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

        if (meta.phone && meta.password && (!state.session || stale(meta))) {
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

        return {
          baseURL: BASE,
          apiKey: state.session,
          headers: gatewayHeaders(state.session),
          async fetch(input, init) {
            let response = await send(input, init, state.session);
            if (response.status === 401 && !state.retried && meta.phone && meta.password) {
              state.retried = true;
              try {
                await response.body?.cancel();
              } catch {
                // 忽略
              }
              try {
                const session = await relogin();
                response = await send(input, init, session);
              } catch (error) {
                log("warn", `session 失效后重登失败：${error.message}`);
              }
            }
            return response;
          },
        };
      },

      async refresh(auth) {
        const meta = metaOf(auth);
        if (!meta.phone || !meta.password) return;
        const got = await login(meta.phone, meta.password, meta.identity);
        return {
          key: got.session,
          expires: Date.now() + SESSION_TTL,
          metadata: {
            ...meta,
            userId: got.userid || meta.userId,
            identity: got.identity,
            obtainedAt: Date.now(),
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
          const data = payload.data || {};
          const available = Number(data.availableBalance ?? data.available);
          const balance = Number(data.balance);
          const daily = Number(data.dailyBalance);
          const parts = [];
          if (Number.isFinite(available)) parts.push(`可用 ${available}`);
          if (Number.isFinite(balance)) parts.push(`余额 ${balance}`);
          if (Number.isFinite(daily)) parts.push(`每日 ${daily}`);
          return {
            plan: "Loomy",
            user: meta.phone || auth?.accountId || "",
            balance: parts.length ? parts.join(" · ") + " 积分" : undefined,
          };
        } catch (error) {
          return { error: `额度查询失败：${error.message}`, windows: [] };
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
          return mergeModels(base, payload.data || payload.models || []);
        } catch (error) {
          log("warn", `拉取模型列表失败，沿用内置清单：${error.message}`);
          return base;
        }
      },
    },

    "chat.headers": async (input, output) => {
      if (input?.model?.providerID === PROVIDER) {
        output.headers["x-loomy-plugin"] = `opencode-loomy-auth/${VERSION}`;
      }
    },
  };
};
