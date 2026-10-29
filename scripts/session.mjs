#!/usr/bin/env bun
// 打印本机 Loomy 桌面端当前登录态（只读，不改客户端文件）。
// 输出里的 session/loggedInAt 就是「自动导入」保存的桌面端凭据；magpie 会按
// loggedInAt 推算过期时间，并在到期前重新读取客户端登录态自动续期。
import { readDesktopSession } from "../lib/desktop.mjs";

const found = readDesktopSession();
if (!found) {
  console.error("未找到 Loomy 桌面端登录态：请先在 Loomy 客户端登录，或用短信/密码方式。");
  process.exit(1);
}
console.log(JSON.stringify(found, null, 2));
