#!/usr/bin/env bun
// 打印本机 Loomy 桌面端当前登录态里的 session（只读，不改客户端文件）。
import { readDesktopSession } from "../lib/desktop.mjs";

const found = readDesktopSession();
if (!found) {
  console.error("未找到 Loomy 桌面端登录态：请先在 Loomy 客户端登录，或用短信/密码方式。");
  process.exit(1);
}
console.log(JSON.stringify(found, null, 2));
