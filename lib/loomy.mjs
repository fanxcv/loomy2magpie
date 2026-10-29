// Loomy（讯飞）账号服务 + 模型网关的最小移植。
// 源自 loomy2api 的 signer.py / crypto.py / account.py / upstream.py，
// 只保留 magpie 插件需要的部分：登录、session、签名、模型与积分查询。

import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";

export const PROVIDER = "loomy";
// LOOMY_BASE_URL 可覆盖（自建反代 / 本地桩测试用），须以 /api/v1 结尾。
export const BASE = String(process.env.LOOMY_BASE_URL || "https://loomyad.xunfei.cn/api/v1").replace(/\/+$/, "");
const ACCOUNT_BASE = process.env.LOOMY_ACCOUNT_BASE_URL || "https://account.xfinfr.com";
const APPID = "GM3LOOMY";
const AK_ID = "2thryby66wxi53sk";
const AK_SECRET = "zsak6eadrbawz683wf5r3m2snrwj868r";
const LOOMY_VERSION = "0.9.38";
const CLIENT_UA = "Loomy|Desktop|Electron|macOS";
const CLIENT_VERSION = "1.0.0";
const WEB_MODEL_ID = "Web";
export const SESSION_TTL = 14 * 24 * 3600 * 1000;
// 控制面请求（登录、短信、模型/积分查询）只等 20 秒；网关转发不设超时，
// 否则会把流式回答截断。
const CONTROL_TIMEOUT = 20_000;

// ---------------------------------------------------------------- 签名

const EXTRA_ESCAPES = { "!": "%21", "'": "%27", "(": "%28", ")": "%29", "*": "%2A" };

function escape(value) {
  return encodeURIComponent(String(value ?? "")).replace(/[!'()*]/g, (c) => EXTRA_ESCAPES[c]);
}

export function contentMD5(body) {
  return body ? createHash("md5").update(body, "utf8").digest("base64") : "";
}

function escapedPath(path) {
  let p = path.startsWith("/") ? path : "/" + path;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p.split("/").map(escape).join("/");
}

function escapedQuery(query) {
  return Object.entries(query || {})
    .map(([k, v]) => `${escape(k)}=${escape(v ?? "")}`)
    .join("&");
}

function canonicalized(headers) {
  const picked = Object.entries(headers || {})
    .filter(([k]) => k.toLowerCase().startsWith("x-"))
    .map(([k, v]) => [k.toLowerCase(), String(v).trim()])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (!picked.length) return { signed: "", value: "" };
  return {
    signed: picked.map(([k]) => k).join(";"),
    value: picked.map(([k, v]) => `${k}:${v}`).join("\n"),
  };
}

export function stringToSign({
  method,
  path,
  query,
  body = "",
  contentType = "application/json",
  date,
  nonce,
  customHeaders,
}) {
  const c = canonicalized(customHeaders);
  return [
    method.toUpperCase(),
    escapedPath(path),
    escapedQuery(query),
    contentMD5(body),
    contentType,
    date,
    nonce,
    c.signed,
    c.value,
  ].join("\n");
}

export function sign({ secret, ...rest }) {
  return createHmac("sha1", secret)
    .update(stringToSign(rest), "utf8")
    .digest("base64");
}

export function buildAuthHeaders(path, body) {
  const date = new Date().toUTCString();
  const nonce = randomUUID();
  const signature = sign({
    secret: AK_SECRET,
    method: "POST",
    path,
    body,
    date,
    nonce,
  });
  const headers = {
    Authorization: `account ${AK_ID}:${signature}`,
    Date: date,
    Nonce: nonce,
    "Content-Type": "application/json",
  };
  const md5 = contentMD5(body);
  if (md5) headers["Content-MD5"] = md5;
  return headers;
}

// ---------------------------------------------------------------- RSA

function readDer(buf, pos) {
  const tag = buf[pos++];
  let len = buf[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[pos++];
  }
  return { tag, pos, len };
}

export function derToNumbers(der) {
  let r = readDer(der, 0);
  if (r.tag !== 0x30) throw new Error("not a DER SEQUENCE");

  r = readDer(der, r.pos);
  if (r.tag !== 0x30) throw new Error("missing AlgorithmIdentifier");
  let pos = r.pos + r.len;

  r = readDer(der, pos);
  if (r.tag !== 0x03) throw new Error("missing BIT STRING");
  if (der[r.pos] !== 0x00) throw new Error("unexpected unused bits in BIT STRING");
  pos = r.pos + 1;

  r = readDer(der, pos);
  if (r.tag !== 0x30) throw new Error("missing RSAPublicKey");
  pos = r.pos;

  const values = [];
  for (let i = 0; i < 2; i++) {
    r = readDer(der, pos);
    if (r.tag !== 0x02) throw new Error("expected INTEGER");
    const bytes = der.subarray(r.pos, r.pos + r.len);
    values.push(bytes.length ? BigInt("0x" + bytes.toString("hex")) : 0n);
    pos = r.pos + r.len;
  }
  return values;
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

export function rsaEncrypt(pubkeyB64, plaintext, rng) {
  const b64 = String(pubkeyB64).replace(/\s+/g, "");
  const der = Buffer.from(b64 + "=".repeat((4 - (b64.length % 4)) % 4), "base64");
  const [n, e] = derToNumbers(der);
  const k = Math.ceil(n.toString(2).length / 8);
  const message = Buffer.from(plaintext, "utf8");
  if (message.length > k - 11) throw new Error(`message too long for RSA-${k * 8}`);

  const padLen = k - message.length - 3;
  let pad;
  if (rng) {
    pad = Buffer.from(rng);
    if (pad.length !== padLen) throw new Error("rng produced wrong length");
  } else {
    do pad = randomBytes(padLen);
    while (pad.includes(0));
  }
  const block = Buffer.concat([Buffer.from([0, 2]), pad, Buffer.from([0]), message]);
  const hex = modPow(BigInt("0x" + block.toString("hex")), e, n)
    .toString(16)
    .padStart(k * 2, "0");
  return Buffer.from(hex, "hex").toString("base64");
}

// ---------------------------------------------------------------- 账号

export function newIdentity() {
  return {
    devid: "web-" + randomBytes(8).toString("hex"),
    ua: CLIENT_UA,
    modelid: WEB_MODEL_ID,
    version: CLIENT_VERSION,
    campus_device_id: "loomy-campus-" + randomUUID(),
    created_at: Date.now(),
  };
}

function base(identity) {
  const id = identity || newIdentity();
  return {
    appid: APPID,
    modelid: id.modelid || WEB_MODEL_ID,
    version: id.version || CLIENT_VERSION,
    devid: id.devid || "web",
    ua: id.ua || CLIENT_UA,
    traceid: randomUUID().replace(/-/g, ""),
  };
}

async function accountCall(path, body) {
  const bodyStr = body ? JSON.stringify(body) : "";
  let res;
  try {
    res = await fetch(ACCOUNT_BASE + path, {
      method: "POST",
      headers: buildAuthHeaders(path, bodyStr),
      body: bodyStr || undefined,
      signal: AbortSignal.timeout(CONTROL_TIMEOUT),
    });
  } catch (error) {
    throw new Error(`账号服务不可达：${error.message}`);
  }
  const text = await res.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error(`${path} HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  const rawCode = payload.code ?? payload.errorCode;
  const code = rawCode === 0 || rawCode === "0" ? "" : String(rawCode ?? "");
  if (code && code !== "000000") {
    throw new Error(`${path}: ${payload.desc || payload.message || code} (${code})`);
  }
  if (res.status >= 400 && payload.message) {
    throw new Error(`${path} HTTP ${res.status}: ${payload.message}`);
  }
  return payload;
}

function extractSession(payload, fallbackPhone) {
  const node = payload.data && typeof payload.data === "object" ? payload.data : payload;
  const session = String(node.session || "");
  if (!session) throw new Error("登录成功但未返回 session");
  return {
    session,
    userid: String(node.userid || node.userId || ""),
    phone: String(node.phone || node.loginid || fallbackPhone || ""),
  };
}

export async function login(phone, password, identity) {
  const id = identity || newIdentity();
  const keyPayload = await accountCall("/login/account/getPuKey", { base: base(id) });
  const pk = keyPayload.data || {};
  if (!pk.pukey) throw new Error("getPuKey 未返回公钥");

  const payload = await accountCall("/login/account/byPwd", {
    base: base(id),
    param: {
      loginid: phone,
      password: rsaEncrypt(pk.pukey, password),
      rcode: pk.rcode || "",
      type: 1,
      expire: SESSION_TTL / 1000,
    },
  });
  return { ...extractSession(payload, phone), identity: id };
}

export async function sendSmsCode(phone, identity) {
  return accountCall("/login/phone/sendMsgCode", {
    base: base(identity || newIdentity()),
    param: { ccode: "86", phone, expire: 300 },
  });
}

export async function loginWithSms(phone, code, msgid, identity) {
  const id = identity || newIdentity();
  const payload = await accountCall("/login/phone/checkCode", {
    base: base(id),
    param: {
      ccode: "86",
      phone,
      mcode: code,
      msgid,
      expire: SESSION_TTL / 1000,
    },
  });
  return { ...extractSession(payload, phone), identity: id };
}

// ---------------------------------------------------------------- 网关

export function gatewayHeaders(session) {
  return {
    Accept: "application/json",
    "Content-Type": "application/json",
    Authorization: `Bearer ${session}`,
    token: session,
    traceparent: `00-${randomUUID().replace(/-/g, "")}-${randomBytes(8).toString("hex")}-01`,
    "loomy-version": LOOMY_VERSION,
  };
}

export async function fetchModels(session) {
  const res = await fetch(`${BASE}/models`, {
    headers: gatewayHeaders(session),
    signal: AbortSignal.timeout(CONTROL_TIMEOUT),
  });
  if (!res.ok) throw withStatus(new Error(`/models HTTP ${res.status}`), res.status);
  return res.json();
}

const POINTS_ROOT = BASE.replace(/\/api\/v1$/, "/api");

// 客户端积分详情页用的是 v2 流水接口；v1 是 loomy2api 记录的旧路径，留作回退。
const POINTS_URLS = [
  `${POINTS_ROOT}/v2/points/records?pageNo=1&pageSize=1&direction=debit&granularity=chat`,
  `${BASE}/points/records?record_type=all&page_no=1&page_size=1`,
];

export async function fetchPoints(session) {
  let lastError;
  for (const url of POINTS_URLS) {
    const res = await fetch(url, {
      headers: gatewayHeaders(session),
      signal: AbortSignal.timeout(CONTROL_TIMEOUT),
    });
    if (res.ok) return res.json();
    lastError = withStatus(new Error(`/points/records HTTP ${res.status}`), res.status);
    if (res.status !== 404) break;
  }
  throw lastError;
}

function withStatus(error, status) {
  error.status = status;
  return error;
}
