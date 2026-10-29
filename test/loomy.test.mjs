import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  contentMD5,
  derToNumbers,
  fetchModels,
  fetchPoints,
  gatewayHeaders,
  login,
  newIdentity,
  rsaEncrypt,
  SESSION_TTL,
  sign,
  stringToSign,
} from "../lib/loomy.mjs";
import {
  FALLBACK_MODELS,
  mergeModels,
  toConfigModel,
  toConfigModels,
  toHookModel,
} from "../lib/models.mjs";
import { readDesktopSession } from "../lib/desktop.mjs";
import { LoomyAuthPlugin } from "../index.mjs";

// 与 loomy2api/tests/test_signer.py、test_crypto.py 相同的黄金向量。
const REAL_PUKEY = [
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNCA0OSvscqyTGPguV7roG6Ct6jqpRVuL1",
  "RtroTH97JBizHdLUaF5Fz9MyKmeFXPVtFn/CINsLzSqxuA8uT4cR5fKmsKlBqAyHNt+sSE+B",
  "6DUDspT5zFPDc/3IeI3/A9sTsl5n1XOLAPjyBodbG2FcDPWp9+MaFoMjaUDvDQ8BJQIDAQAB",
].join("");

const fakeClient = {
  auth: { set: async () => ({ data: {} }) },
  app: { log: () => ({ data: {} }) },
};

function desktopDir(value) {
  const dir = mkdtempSync(join(tmpdir(), "loomy-desktop-"));
  writeFileSync(
    join(dir, "000003.log"),
    Buffer.from("noise loomy-auth-session " + JSON.stringify(value)),
  );
  return dir;
}

describe("signer", () => {
  test("stringToSign is nine lines", () => {
    const got = stringToSign({
      method: "post",
      path: "/login/account/getPuKey",
      body: '{"base":{"appid":"GM3LOOMY"}}',
      date: "Sat, 26 Sep 2026 12:00:00 GMT",
      nonce: "11111111-2222-3333-4444-555555555555",
    });
    expect(got).toBe(
      [
        "POST",
        "/login/account/getPuKey",
        "",
        "ZXFsDbtKIeoeelrBB+sO7g==",
        "application/json",
        "Sat, 26 Sep 2026 12:00:00 GMT",
        "11111111-2222-3333-4444-555555555555",
        "",
        "",
      ].join("\n"),
    );
  });

  test("signature matches the client JS vector", () => {
    expect(
      sign({
        secret: "TEST_SECRET",
        method: "POST",
        path: "/login/account/getPuKey",
        body: '{"base":{"appid":"GM3LOOMY"}}',
        date: "Sat, 26 Sep 2026 12:00:00 GMT",
        nonce: "11111111-2222-3333-4444-555555555555",
      }),
    ).toBe("hu4CwF8SGwW9+0aCwfU7idd7gho=");
  });

  test("query, trailing slash and custom headers", () => {
    const args = {
      secret: "TEST_SECRET",
      method: "POST",
      path: "/login/phone/checkCode/",
      query: { a: "1 2", b: "x(y)" },
      body: "",
      date: "Sat, 26 Sep 2026 12:00:00 GMT",
      nonce: "nonce-2",
      customHeaders: { "X-Test": " v1 ", "x-other": "2" },
    };
    expect(sign(args)).toBe("53bKaJEgHxiy8d7lYUMWFhmLtY0=");
    expect(stringToSign(args)).toBe(
      [
        "POST",
        "/login/phone/checkCode",
        "a=1%202&b=x%28y%29",
        "",
        "application/json",
        "Sat, 26 Sep 2026 12:00:00 GMT",
        "nonce-2",
        "x-other;x-test",
        "x-other:2\nx-test:v1",
      ].join("\n"),
    );
  });

  test("content md5", () => {
    expect(contentMD5("")).toBe("");
    expect(contentMD5("abc")).toBe("kAFQmDzST7DWlj99KOF/cg==");
  });
});

describe("rsa", () => {
  test("parses the live account-service public key", () => {
    const [n, e] = derToNumbers(Buffer.from(REAL_PUKEY, "base64"));
    expect(e).toBe(65537n);
    expect(n.toString(2).length).toBe(1024);
  });

  test("PKCS#1 v1.5 ciphertext matches the Python port byte-for-byte", () => {
    expect(rsaEncrypt(REAL_PUKEY, "hunter2", Buffer.alloc(118, 0x41))).toBe(
      "eKpJGtson30i8TbQP7VchbWaoQvruKSKyfCMEFMyuR1u7FZ7M7UOzqpkuF/2LlyI1gO3d17ka6JgulJCJYoee3wdgRuRcmHkA356Ta2GfZbQ7ivpWlggNM/0X1uI6jzTYPBEzq1jUc6ZUn37NZJLyT1qi2XMWRX9sZDGorMhFXU=",
    );
  });

  test("rejects messages longer than the modulus", () => {
    expect(() => rsaEncrypt(REAL_PUKEY, "x".repeat(200))).toThrow("too long");
  });
});

describe("gateway headers", () => {
  test("sends both auth forms plus traceparent", () => {
    const headers = gatewayHeaders("SESSION");
    expect(headers.Authorization).toBe("Bearer SESSION");
    expect(headers.token).toBe("SESSION");
    expect(headers.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    expect(headers["loomy-version"]).toBe("0.9.38");
  });
});

describe("model catalogue", () => {
  test("fallback models map to the OpenCode config shape", () => {
    const models = toConfigModels(FALLBACK_MODELS);
    expect(models["deepseek-v4-flash-0731"].limit.context).toBe(1048576);
    expect(models["mimo-v2.5"].attachment).toBe(true);
    expect(models["spark-x"].attachment).toBe(false);
    expect(models["mimo-v2.5"].tool_call).toBe(true);
    expect(models["mimo-v2.5"].modalities.input).toEqual(["text", "image", "audio", "video"]);
  });

  test("toConfigModel keeps the OpenCode fields", () => {
    const model = toConfigModel({
      id: "m",
      name: "M",
      context_length: 1000,
      max_output_tokens: 200,
      reasoning: true,
      tool_call: false,
      modalities: ["text", "image"],
    });
    expect(model).toMatchObject({
      id: "m",
      name: "M",
      limit: { context: 1000, output: 200 },
      reasoning: true,
      tool_call: false,
      attachment: true,
      modalities: { input: ["text", "image"], output: ["text"] },
    });
  });

  test("hook models strip the points multiplier into rate", () => {
    const model = toHookModel({
      id: "spark-x",
      name: "Spark X2.5 (x0.1)",
      context_length: 1048576,
      modalities: ["text"],
    });
    expect(model.name).toBe("Spark X2.5");
    expect(model.rate).toBe(0.1);
    expect(model.free).toBeUndefined();
    expect(model.limit.context).toBe(1048576);
    expect(model.capabilities.toolcall).toBe(true);
  });

  test("a zero multiplier is free and leaves no rate", () => {
    const model = toHookModel({ id: "free", name: "Free Model (x0.00)" });
    expect(model.name).toBe("Free Model");
    expect(model.free).toBe(true);
    expect(model.rate).toBeUndefined();
  });

  test("modalities fill the GUI capabilities", () => {
    const model = toHookModel({
      id: "mimo-v2.5",
      name: "MiMo V2.5 (x3.3)",
      modalities: ["text", "image", "audio"],
    });
    expect(model.capabilities.input).toEqual({
      text: true,
      image: true,
      audio: true,
      video: false,
      pdf: false,
    });
    expect(model.capabilities.output).toEqual({ text: true });
  });

  test("hook models keep the base fields and inherit its reasoning", () => {
    const base = {
      api: { npm: "@ai-sdk/openai-compatible", url: "https://x", id: "m" },
      cost: { input: 0, output: 0 },
      variants: { low: { reasoningEffort: "low" } },
      limit: { context: 1, output: 2 },
      capabilities: { reasoning: true, input: { text: true } },
    };
    const model = toHookModel({ id: "m", name: "M (x2.0)" }, base);
    expect(model.api).toEqual(base.api);
    expect(model.cost).toEqual(base.cost);
    expect(model.variants).toEqual(base.variants);
    expect(model.capabilities.reasoning).toBe(true);
    expect(model.rate).toBe(2);
  });

  test("upstream list is authoritative but keeps the base shape", () => {
    const base = toConfigModels(FALLBACK_MODELS);
    const merged = mergeModels(base, [
      { id: "spark-x", name: "Spark X2.5 (x0.1)", modalities: ["text", "image"] },
    ]);
    expect(Object.keys(merged)).toEqual(["spark-x"]);
    expect(merged["spark-x"].name).toBe("Spark X2.5");
    expect(merged["spark-x"].rate).toBe(0.1);
    expect(merged["spark-x"].limit.context).toBe(1048576);
    expect(merged["spark-x"].capabilities.input.image).toBe(true);
  });

  test("empty upstream result falls back to the provided list", () => {
    const base = toConfigModels(FALLBACK_MODELS);
    expect(mergeModels(base, [])).toBe(base);
  });
});

describe("plugin hooks", () => {
  test("config seeds the loomy provider", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    const cfg = {};
    await hooks.config(cfg);
    expect(cfg.provider.loomy.api).toBe("https://loomyad.xunfei.cn/api/v1");
    expect(cfg.provider.loomy.npm).toBe("@ai-sdk/openai-compatible");
    expect(Object.keys(cfg.provider.loomy.models).length).toBeGreaterThan(5);
  });

  test("loader turns the login into gateway headers", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    const loader = await hooks.auth.loader(async () => ({ type: "api", key: "S1" }));
    expect(loader.baseURL).toBe("https://loomyad.xunfei.cn/api/v1");
    expect(loader.apiKey).toBe("S1");
    expect(loader.headers.token).toBe("S1");
  });

  test("loader without auth still returns a usable shape", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    expect(await hooks.auth.loader(async () => null)).toEqual({});
  });

  test("loader reads oauth access tokens too", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    const loader = await hooks.auth.loader(async () => ({
      type: "oauth",
      access: "A1",
      expires: Date.now() + 86400000,
      phone: "13800138000",
    }));
    expect(loader.apiKey).toBe("A1");
    expect(loader.headers.token).toBe("A1");
  });

  test("auth declares a 24h renewal lead", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    expect(hooks.auth.refreshLead).toBe(24 * 3600 * 1000);
  });

  for (const status of [401, 403]) {
    test(`a ${status} with no password to re-login is marked expired`, async () => {
      const original = globalThis.fetch;
      globalThis.fetch = async () => new Response("upstream body", { status });
      try {
        const hooks = await LoomyAuthPlugin({ client: fakeClient });
        const loader = await hooks.auth.loader(async () => ({ type: "api", key: "S" }));
        const response = await loader.fetch("https://loomyad.xunfei.cn/api/v1/chat/completions", {
          method: "POST",
          body: "{}",
        });
        expect(response.status).toBe(status);
        expect(response.headers.get("X-Magpie-Sign-In")).toBe("expired");
        expect(await response.text()).toBe("upstream body");
      } finally {
        globalThis.fetch = original;
      }
    });
  }

  test("has four sign-in methods, desktop import first", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    expect(hooks.auth.methods.map((m) => m.label)).toEqual([
      "自动导入 Loomy 桌面端登录态",
      "手机号 + 短信验证码",
      "Loomy 手机号 + 密码",
      "粘贴已有 session（不存密码）",
    ]);
  });

  test("paste-session method stays a plain api method", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    const method = hooks.auth.methods[3];
    expect(method.type).toBe("api");
    expect(method.authorize).toBeUndefined();
  });

  test("the password and desktop methods are keyless so magpie does not ask for an API key", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    expect(hooks.auth.methods[0].keyless).toBe(true);
    expect(typeof hooks.auth.methods[0].authorize).toBe("function");
    expect(hooks.auth.methods[2].keyless).toBe(true);
    expect(typeof hooks.auth.methods[2].authorize).toBe("function");
  });
});

describe("login flow (mocked account service)", () => {
  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "content-type": "application/json" },
    });

  test("signs both calls, encrypts the password and returns the session", async () => {
    const original = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/login/account/getPuKey")) {
        return json({ code: "000000", data: { pukey: REAL_PUKEY, rcode: "rc" } });
      }
      if (String(url).endsWith("/login/account/byPwd")) {
        const body = JSON.parse(init.body);
        return json({
          code: "000000",
          data: { session: "S-1", userid: "U-1", phone: body.param.loginid },
        });
      }
      return json({ code: "404" }, 404);
    };

    try {
      const got = await login("13800138000", "pw", newIdentity());
      expect(got).toMatchObject({ session: "S-1", userid: "U-1", phone: "13800138000" });
      expect(calls).toHaveLength(2);

      const [, byPwd] = calls;
      expect(byPwd.init.headers.Authorization).toMatch(/^account 2thryby66wxi53sk:/);
      expect(byPwd.init.headers.Nonce).toBeTruthy();
      expect(byPwd.init.headers["Content-MD5"]).toBeTruthy();

      const body = JSON.parse(byPwd.init.body);
      expect(Buffer.from(body.param.password, "base64").length).toBe(128);
      expect(body.param.expire).toBe(14 * 24 * 3600);
      expect(body.base.appid).toBe("GM3LOOMY");
      expect(body.base.traceid).toMatch(/^[0-9a-f]{32}$/);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("a 401 on the gateway triggers one re-login and a retry", async () => {
    const original = globalThis.fetch;
    let gatewayCalls = 0;
    let logins = 0;
    globalThis.fetch = async (url, init) => {
      if (String(url).includes("account.xfinfr.com")) {
        if (String(url).endsWith("/getPuKey")) {
          return json({ code: "000000", data: { pukey: REAL_PUKEY, rcode: "" } });
        }
        logins++;
        return json({ code: "000000", data: { session: "S-NEW", userid: "U" } });
      }
      gatewayCalls++;
      return new Response("", { status: gatewayCalls === 1 ? 401 : 200 });
    };

    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const auth = {
        type: "api",
        key: "S-OLD",
        metadata: { phone: "13800138000", password: "pw", obtainedAt: Date.now() },
      };
      const loader = await hooks.auth.loader(async () => auth);
      const response = await loader.fetch("https://loomyad.xunfei.cn/api/v1/chat/completions", {
        method: "POST",
        body: "{}",
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("X-Magpie-Sign-In")).toBeNull();
      expect(logins).toBe(1);
      expect(gatewayCalls).toBe(2);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("control-plane requests time out while the gateway fetch keeps streaming", async () => {
    const original = globalThis.fetch;
    const signals = [];
    globalThis.fetch = async (url, init) => {
      signals.push(init?.signal);
      if (String(url).endsWith("/getPuKey")) {
        return json({ code: "000000", data: { pukey: REAL_PUKEY, rcode: "" } });
      }
      if (String(url).endsWith("/byPwd")) {
        return json({ code: "000000", data: { session: "S" } });
      }
      if (String(url).endsWith("/models")) return json({ data: [] });
      if (String(url).includes("/points/records")) return json({ code: "000000", data: {} });
      return json({ code: "000000" });
    };
    try {
      await login("1", "pw", newIdentity());
      await fetchModels("S");
      await fetchPoints("S");
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      await hooks.auth.checkin(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(signals).toHaveLength(5);
      expect(signals.every((signal) => signal instanceof AbortSignal)).toBe(true);

      let gatewaySignal = "unset";
      globalThis.fetch = async (_url, init) => {
        gatewaySignal = init?.signal;
        return new Response("", { status: 200 });
      };
      const loader = await hooks.auth.loader(async () => ({ type: "api", key: "S" }));
      await loader.fetch("https://loomyad.xunfei.cn/api/v1/chat/completions", { body: "{}" });
      expect(gatewaySignal).toBeUndefined();
    } finally {
      globalThis.fetch = original;
    }
  });

  test("a failed re-login marks the response as expired", async () => {
    const original = globalThis.fetch;
    let gatewayCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes("account.xfinfr.com")) return json({ code: "100003", desc: "密码错误" });
      gatewayCalls++;
      return new Response("nope", { status: 401 });
    };
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const auth = {
        type: "api",
        key: "S-OLD",
        metadata: { phone: "13800138000", password: "wrong", obtainedAt: Date.now() },
      };
      const loader = await hooks.auth.loader(async () => auth);
      const response = await loader.fetch("https://loomyad.xunfei.cn/api/v1/chat/completions", {
        method: "POST",
        body: "{}",
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("X-Magpie-Sign-In")).toBe("expired");
      expect(gatewayCalls).toBe(1);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("authorize returns a saved api auth with the session as key", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async (url) => {
      if (String(url).endsWith("/getPuKey")) {
        return json({ code: "000000", data: { pukey: REAL_PUKEY, rcode: "" } });
      }
      return json({ code: "000000", data: { session: "S-AUTH", userid: "U-9", phone: "13800138000" } });
    };
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.methods[2].authorize({
        phone: "13800138000",
        password: "pw",
      });
      expect(result.type).toBe("success");
      expect(result.key).toBe("S-AUTH");
      expect(result.metadata.email).toBe("13800138000");
      expect(result.metadata.password).toBe("pw");

      // 模拟 magpie host.js 的 save(): inputs 与 result.metadata 合并，只留 key/metadata。
      const stored = {
        type: "api",
        key: result.key,
        metadata: { phone: "13800138000", password: "pw", ...result.metadata },
      };
      const loader = await hooks.auth.loader(async () => stored);
      expect(loader.apiKey).toBe("S-AUTH");
      expect(loader.headers.token).toBe("S-AUTH");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("authorize reports account-service failures", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => json({ code: "100003", desc: "密码错误" });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.methods[2].authorize({ phone: "1", password: "x" });
      expect(result.type).toBe("failed");
      expect(result.error).toContain("密码错误");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("usage maps the points record to a wallet window magpie can route on", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () =>
      json({
        code: "000000",
        data: { balance: 100, dailyBalance: 20, availableBalance: 120, planName: "Pro" },
      });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const usage = await hooks.auth.usage(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(usage.balance).toBe("120 积分");
      expect(usage.plan).toBe("Pro");
      expect(usage.user).toBe("");
      expect(usage.windows).toHaveLength(1);
      const window = usage.windows[0];
      expect(window.balance).toBe(120);
      expect(window.unit).toBe("积分");
      expect(window.span).toBe(86400);
      expect(window.runsOut).toBe(20);
      expect(Date.parse(window.resetsAt)).toBeGreaterThan(Date.now());
      // 一个钱包窗口 = 路由知道这个账号（不再是 unknown 排在已知账号之后）
      expect(window.used).toBeUndefined();
    } finally {
      globalThis.fetch = original;
    }
  });

  test("a real zero available balance is not replaced by the local sum", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () =>
      json({
        code: "000000",
        data: { balance: 100, dailyBalance: 20, availableBalance: 0 },
      });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const usage = await hooks.auth.usage(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(usage.balance).toBe("0 积分");
      expect(usage.windows[0].balance).toBe(0);
      expect(usage.windows[0].display).toContain("可用 0");
      expect(usage.plan).toBe("");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("checkin uses magpie's claimed outcome", async () => {
    const original = globalThis.fetch;
    let seen;
    globalThis.fetch = async (url, init) => {
      seen = { url: String(url), method: init.method, body: init.body, signal: init.signal };
      return json({ code: "000000" });
    };
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.checkin(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(result.outcome).toBe("claimed");
      expect(seen.url).toBe("https://loomyad.xunfei.cn/api/v1/points/first-login");
      expect(seen.method).toBe("POST");
      expect(seen.signal).toBeInstanceOf(AbortSignal);
      // until 落在北京日 0 点，且在将来
      const until = Date.parse(result.until);
      expect(new Date(until).toISOString()).toBe(result.until);
      expect(until).toBeGreaterThan(Date.now());
      expect((until + 8 * 3600 * 1000) % 86400000).toBe(0);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("checkin treats an already-claimed day as done", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => json({ code: "100002", desc: "今日已签到" });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.checkin(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(result.outcome).toBe("done");
      expect(result.message).toBe("今日已签到");
      expect(Date.parse(result.until)).toBeGreaterThan(Date.now());
    } finally {
      globalThis.fetch = original;
    }
  });

  test("checkin keeps other upstream failures as failed", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => json({ code: "100003", desc: "活动已结束" });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.checkin(async () => ({ type: "api", key: "S", metadata: {} }));
      expect(result).toEqual({ outcome: "failed", message: "活动已结束" });
    } finally {
      globalThis.fetch = original;
    }
  });

  test("provider models marks a dead session for magpie", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => json({ code: "020002", desc: "登录已失效" });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      let seen;
      try {
        await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "S" } });
      } catch (error) {
        seen = error;
      }
      expect(seen.message).toBe("登录已失效");
      expect(seen.signIn).toBe("expired");
    } finally {
      globalThis.fetch = original;
    }
  });

  test("provider models returns the GUI shape with capabilities and rate", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () =>
      json({
        code: "000000",
        data: [{ id: "spark-x", name: "Spark X2.5 (x0.1)", modalities: ["text", "image"] }],
      });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const models = await hooks.provider.models({ models: {} }, { auth: { type: "api", key: "S" } });
      expect(models["spark-x"].name).toBe("Spark X2.5");
      expect(models["spark-x"].rate).toBe(0.1);
      expect(models["spark-x"].capabilities.input.image).toBe(true);
      expect(models["spark-x"].capabilities.toolcall).toBe(true);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("sms and desktop import", () => {
  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), {
      status,
      headers: { "content-type": "application/json" },
    });

  test("sms authorize sends a code and callback exchanges it for a session", async () => {
    const original = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: init?.body ? JSON.parse(init.body) : null });
      if (String(url).endsWith("/login/phone/sendMsgCode")) {
        return json({ code: "000000", data: { msgid: "M-1" } });
      }
      if (String(url).endsWith("/login/phone/checkCode")) {
        return json({ code: "000000", data: { session: "S-SMS", userid: "U-SMS", phone: "13800138000" } });
      }
      return json({ code: "404" }, 404);
    };
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const started = await hooks.auth.methods[1].authorize({ phone: "13800138000" });
      expect(started.method).toBe("code");
      expect(started.instructions).toContain("13800138000");

      const result = await started.callback("123456");
      expect(result.type).toBe("success");
      expect(result.access).toBe("S-SMS");
      expect(result.accountId).toBe("13800138000");
      // 滑动 TTL：不写本地过期，是否失效只由服务端（401/100002）说了算。
      expect("expires" in result).toBe(false);

      const check = calls.find((c) => c.url.endsWith("/login/phone/checkCode"));
      expect(check.body.param.msgid).toBe("M-1");
      expect(check.body.param.mcode).toBe("123456");
      expect(check.body.param.expire).toBe(14 * 24 * 3600);
    } finally {
      globalThis.fetch = original;
    }
  });

  test("desktop import reads the leveldb log as a renewable oauth sign-in", async () => {
    const loggedInAt = Date.now() - 60_000;
    const dir = desktopDir({
      phone: "13900139000",
      session: "S-DESK",
      userid: "U-DESK",
      loggedInAt,
    });

    const original = globalThis.fetch;
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = dir;
    let modelCalls = 0;
    globalThis.fetch = async () => {
      modelCalls++;
      return json({ data: [{ id: "spark-x" }] });
    };
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.methods[0].authorize();
      expect(result.type).toBe("success");
      expect(result.access).toBe("S-DESK");
      expect(result.key).toBeUndefined();
      // host 的 save() 以 "refresh" in result 判定 oauth；桌面端没有真 refresh token。
      expect("refresh" in result).toBe(true);
      expect(result.refresh).toBe("");
      expect(result.source).toBe("desktop");
      expect(result.accountId).toBe("13900139000");
      expect(result.phone).toBe("13900139000");
      expect(result.userId).toBe("U-DESK");
      expect(result.expires).toBe(loggedInAt + SESSION_TTL);
      expect(modelCalls).toBe(1);
    } finally {
      globalThis.fetch = original;
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });

  test("a masked phone is not used as the desktop account identity", async () => {
    const dir = desktopDir({
      maskedPhone: "139****9000",
      session: "S-MASK",
      userid: "U-MASK",
      loggedInAt: Date.now(),
    });
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = dir;
    try {
      const found = readDesktopSession();
      expect(found.session).toBe("S-MASK");
      expect(found.phone).toBe("");

      const original = globalThis.fetch;
      globalThis.fetch = async () => json({ data: [] });
      try {
        const hooks = await LoomyAuthPlugin({ client: fakeClient });
        const result = await hooks.auth.methods[0].authorize();
        expect(result.accountId).toBeUndefined();
        expect(result.phone).toBe("");
      } finally {
        globalThis.fetch = original;
      }
    } finally {
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });

  test("desktop import fails cleanly when nothing is installed", async () => {
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = mkdtempSync(join(tmpdir(), "loomy-empty-"));
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const result = await hooks.auth.methods[0].authorize();
      expect(result.type).toBe("failed");
      expect(result.error).toContain("未找到");
    } finally {
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });
});

describe("desktop renewal", () => {
  test("refresh picks up a new desktop session", async () => {
    const loggedInAt = Date.now() - 5_000;
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = desktopDir({
      phone: "13900139000",
      session: "S-NEW",
      userid: "U-NEW",
      loggedInAt,
    });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const got = await hooks.auth.refresh({
        type: "oauth",
        access: "S-OLD",
        refresh: "",
        expires: Date.now(),
        source: "desktop",
      });
      expect(got).toMatchObject({
        access: "S-NEW",
        refresh: "",
        phone: "13900139000",
        userId: "U-NEW",
      });
      // 不带 source：host 用 {...was, ...fields} 合并，原有 source 得以保留。
      expect(got.source).toBeUndefined();
      expect(got.expires).toBe(loggedInAt + SESSION_TTL);
    } finally {
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });

  test("refresh has nothing to do when the desktop session is unchanged or absent", async () => {
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = desktopDir({
      phone: "13900139000",
      session: "S-SAME",
      loggedInAt: Date.now(),
    });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      expect(await hooks.auth.refresh({ type: "oauth", access: "S-SAME", source: "desktop" })).toBeUndefined();

      process.env.LOOMY_DESKTOP_DIR = mkdtempSync(join(tmpdir(), "loomy-empty-"));
      expect(await hooks.auth.refresh({ type: "oauth", access: "S-SAME", source: "desktop" })).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });

  test("refresh leaves every other account type alone", async () => {
    const hooks = await LoomyAuthPlugin({ client: fakeClient });
    expect(await hooks.auth.refresh({ type: "oauth", access: "A", source: "sms" })).toBeUndefined();
    expect(
      await hooks.auth.refresh({
        type: "api",
        key: "K",
        metadata: { phone: "13800138000", password: "pw" },
      }),
    ).toBeUndefined();
  });

  // 短信账号没有 refresh token，但本机桌面端登录的是同一个手机号时，可以借它的 session。
  test("refresh borrows a desktop session for the same phone", async () => {
    const previous = process.env.LOOMY_DESKTOP_DIR;
    process.env.LOOMY_DESKTOP_DIR = desktopDir({
      phone: "13800138000",
      session: "S-DESKTOP",
      loggedInAt: Date.now(),
    });
    try {
      const hooks = await LoomyAuthPlugin({ client: fakeClient });
      const sms = { type: "oauth", access: "S-SMS", refresh: "", phone: "13800138000" };
      expect((await hooks.auth.refresh(sms)).access).toBe("S-DESKTOP");
      // 手机号不是这一个的账号不借
      expect(await hooks.auth.refresh({ ...sms, phone: "13700137000" })).toBeUndefined();
      expect(await hooks.auth.refresh({ ...sms, accountId: "13700137000" })).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.LOOMY_DESKTOP_DIR;
      else process.env.LOOMY_DESKTOP_DIR = previous;
    }
  });
});
