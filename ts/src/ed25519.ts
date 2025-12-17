import nacl from "tweetnacl";

function b64urlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function parseEd25519Pub(s: string): Uint8Array {
  if (!s.startsWith("ed25519:")) throw new Error("bad pubkey prefix");
  const raw = b64urlToBytes(s.slice("ed25519:".length));
  if (raw.length !== 32) throw new Error("bad pubkey length");
  return raw;
}

export function parseEd25519Sig(s: string): Uint8Array {
  if (!s.startsWith("ed25519sig:")) throw new Error("bad sig prefix");
  const raw = b64urlToBytes(s.slice("ed25519sig:".length));
  if (raw.length !== 64) throw new Error("bad sig length");
  return raw;
}

export function verifyEd25519(msg: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  return nacl.sign.detached.verify(msg, sig, pub);
}

