import crypto from "node:crypto";
import { canonicalString } from "./canon";

export function sha256Domain(tag: string, bytes: Buffer): Buffer {
  const h = crypto.createHash("sha256");
  h.update(Buffer.from(tag, "utf8"));
  h.update(Buffer.from([0]));
  h.update(bytes);
  return h.digest();
}

export function prefixedSha256Hex(d: Buffer): string {
  return "sha256:" + d.toString("hex");
}

export function hashJson(tag: string, v: any): string {
  const canon = canonicalString(v);
  const d = sha256Domain(tag, Buffer.from(canon, "utf8"));
  return prefixedSha256Hex(d);
}

