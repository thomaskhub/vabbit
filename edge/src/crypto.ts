// Token generation, hashing and constant-time comparison (WebCrypto only).

const enc = new TextEncoder();

export function randomToken(prefix: string, bytes = 32): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return prefix + base64url(b);
}

export function randomId(): string {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return hex(b);
}

export async function sha256Hex(s: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));
}

/** Constant-time comparison of two equal-length hex/ASCII strings. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** True if s is a standard base64 encoding of exactly 32 bytes (a WireGuard key). */
export function isWireGuardKey(s: unknown): s is string {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(s)) return false;
  try {
    return atob(s).length === 32;
  } catch {
    return false;
  }
}
