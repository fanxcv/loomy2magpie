// 读取本机 Loomy 桌面端（Electron）的登录态。
// 登录态是 Chromium Local Storage（leveldb）里的明文 JSON，键名 loomy-auth-session：
//   {"phone":…,"maskedPhone":…,"session":…,"userid":…,"loggedInAt":…}
// leveldb 的 .log 是追加写，同一键可能有多份，从后往前取最后一份。
// 解析思路参考 magpie-plugin-loomy（MIT），此处独立实现。

import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const SESSION_KEY = "loomy-auth-session";

function storageDirs() {
  const override = process.env.LOOMY_DESKTOP_DIR;
  if (override) return [override];
  const home = homedir();
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return [path.join(appData, "Loomy", "Local Storage", "leveldb")];
  }
  if (process.platform === "darwin") {
    return [path.join(home, "Library", "Application Support", "Loomy", "Local Storage", "leveldb")];
  }
  const config = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return [path.join(config, "Loomy", "Local Storage", "leveldb")];
}

function jsonAfter(bytes, from) {
  const open = bytes.indexOf(0x7b, from); // "{"
  if (open < 0) return null;
  let depth = 0;
  for (let i = open; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte === 0x22) {
      i++;
      while (i < bytes.length && bytes[i] !== 0x22) {
        if (bytes[i] === 0x5c) i++; // 反斜杠转义
        i++;
      }
      continue;
    }
    if (byte === 0x7b) depth++;
    else if (byte === 0x7d && --depth === 0) {
      try {
        return JSON.parse(bytes.subarray(open, i + 1).toString("utf8"));
      } catch {
        return null;
      }
    }
  }
  return null;
}

function readLogSession(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  const logs = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".log"))
    .map((entry) => entry.name)
    .sort();
  const key = new TextEncoder().encode(SESSION_KEY);
  for (const name of logs.reverse()) {
    let bytes;
    try {
      bytes = readFileSync(path.join(dir, name));
    } catch {
      continue;
    }
    let at = bytes.lastIndexOf(key);
    while (at >= 0) {
      const value = jsonAfter(bytes, at + key.length);
      if (value && typeof value.session === "string" && value.session.trim()) {
        return {
          session: value.session.trim(),
          userid: String(value.userid || value.userId || ""),
          phone: String(value.phone || "").trim(),
          loggedInAt: Number(value.loggedInAt) || Date.now(),
          source: "desktop",
        };
      }
      at = bytes.lastIndexOf(key, at - 1);
    }
  }
  return null;
}

// 旧版客户端把 session 放在 <root>/<hash>/userData/auth-session.json。
function readAuthSessionFiles() {
  if (process.platform !== "win32") return null;
  const root = process.env.LOOMY_CLIENT_ROOT || "C:\\Users\\Public\\Loomy";
  let hashes;
  try {
    hashes = readdirSync(root, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of hashes) {
    if (!entry.isDirectory()) continue;
    const file = path.join(root, entry.name, "userData", "auth-session.json");
    try {
      if (!statSync(file).isFile()) continue;
      const value = JSON.parse(readFileSync(file, "utf8"));
      if (value && typeof value.session === "string" && value.session.trim()) {
        return {
          session: value.session.trim(),
          userid: String(value.userid || value.userId || ""),
          phone: String(value.phone || "").trim(),
          loggedInAt: Number(value.loggedInAt) || Date.now(),
          source: "desktop",
        };
      }
    } catch {
      // 下一个
    }
  }
  return null;
}

export function readDesktopSession() {
  for (const dir of storageDirs()) {
    const found = readLogSession(dir);
    if (found) return found;
  }
  return readAuthSessionFiles();
}
