/**
 * Cloudflare Worker — אימות קודי נוכחות ורישום ב-Firestore.
 *
 * נקודות גישה (POST, גוף JSON עם id, lec, exp, sig):
 *   /names  — מחזיר את רשימת הסטודנטים, רק עבור קוד תקף שעוד לא נוצל
 *   /       — רושם נוכחות (בנוסף צריך name)
 *
 * רשימת הסטודנטים (students.json) נארזת לתוך ה-Worker בזמן הפריסה.
 * היא לא נמצאת ב-GitHub ולא חשופה לציבור.
 *
 * Secrets (wrangler secret put):
 *   HMAC_SECRET               — המפתח הסודי (אותה מחרוזת בדיוק שב-secret.key אצל המרצה)
 *   FIREBASE_SERVICE_ACCOUNT  — תוכן קובץ ה-JSON של ה-service account
 * Vars (wrangler.toml):
 *   ALLOWED_ORIGIN            — כתובת אתר ה-GitHub Pages, למשל https://user.github.io
 */

import students from "../../students.json" with { type: "json" };

const STUDENT_LIST = students.map((s) => s.normalize("NFC").trim());
const STUDENTS = new Set(STUDENT_LIST);

const ID_RE = /^[A-Za-z0-9_-]{22}$/; // 16 בייטים ב-base64url בלי ריפוד
const LEC_RE = /^\d+-\d{4}-\d{2}-\d{2}$/;
const EXP_RE = /^\d{1,12}$/;
const SIG_RE = /^[A-Za-z0-9_-]{43}$/; // 32 בייטים (HMAC-SHA256) ב-base64url

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method" }, 405, cors);
    }

    let body;
    try {
      const text = await request.text();
      if (text.length > 4096) throw new Error("too large");
      body = JSON.parse(text);
    } catch {
      return json({ ok: false, error: "bad_request" }, 400, cors);
    }

    const { id, lec, exp, sig } = body ?? {};
    const name = typeof body?.name === "string" ? body.name.normalize("NFC").trim() : "";

    // 1+2. צורה, חתימה ותוקף
    const codeError = await checkCode(env, { id, lec, exp, sig });
    if (codeError) {
      return json({ ok: false, error: codeError.error }, codeError.status, cors);
    }

    const path = new URL(request.url).pathname.replace(/\/+$/, "");

    // רשימת השמות — רק למי שמחזיק קוד תקף שעוד לא נוצל
    if (path === "/names") {
      try {
        if (await isUsed(env, id)) {
          return json({ ok: false, error: "used" }, 409, cors);
        }
      } catch (err) {
        console.error("firestore error:", err?.message ?? err);
        return json({ ok: false, error: "server" }, 500, cors);
      }
      return json({ ok: true, names: STUDENT_LIST }, 200, cors);
    }
    if (path !== "") {
      return json({ ok: false, error: "not_found" }, 404, cors);
    }

    // אימות שם מול רשימת הסטודנטים
    if (!STUDENTS.has(name)) {
      return json({ ok: false, error: "unknown_name" }, 400, cors);
    }

    // 3+4. כתיבה אטומית: used/{id} + attendance/{id} + registered/{lec+שם}, כולן עם exists=false.
    // אם הקוד כבר נוצל או שהסטודנט כבר נרשם להרצאה — ה-commit כולו נכשל ושום דבר לא נכתב.
    try {
      const result = await recordAttendance(env, { id, lec, name });
      if (result === "used") {
        return json({ ok: false, error: "used" }, 409, cors);
      }
      if (result === "already_registered") {
        return json({ ok: false, error: "already_registered", name }, 409, cors);
      }
      return json({ ok: true, name, lec }, 200, cors);
    } catch (err) {
      console.error("firestore error:", err?.message ?? err);
      return json({ ok: false, error: "server" }, 500, cors);
    }
  },
};

// ---------- בדיקת קוד ----------

async function checkCode(env, { id, lec, exp, sig }) {
  // צורה בסיסית של הפרמטרים — כל דבר אחר הוא "קוד לא תקין"
  if (
    typeof id !== "string" || !ID_RE.test(id) || /^__.*__$/.test(id) ||
    typeof lec !== "string" || !LEC_RE.test(lec) ||
    typeof exp !== "string" || !EXP_RE.test(exp) ||
    typeof sig !== "string" || !SIG_RE.test(sig)
  ) {
    return { error: "invalid", status: 400 };
  }
  // 1. אימות חתימה (crypto.subtle.verify משווה ב-constant time)
  if (!(await verifySignature(env.HMAC_SECRET, `${id}|${lec}|${exp}`, sig))) {
    return { error: "invalid", status: 403 };
  }
  // 2. תוקף
  if (Math.floor(Date.now() / 1000) >= Number(exp)) {
    return { error: "expired", status: 410 };
  }
  return null;
}

// ---------- HMAC ----------

async function verifySignature(secret, message, sigB64url) {
  secret = (secret || "").trim();
  if (!secret) throw new Error("HMAC_SECRET is not configured");
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  let sigBytes;
  try {
    sigBytes = b64urlDecode(sigB64url);
  } catch {
    return false;
  }
  return crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(message));
}

// ---------- Firestore ----------

// בדיקה בלבד (לתצוגת הרשימה). מניעת השימוש הכפול עצמה נעשית ב-commit האטומי.
async function isUsed(env, id) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getAccessToken(sa);
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents/used/${id}?mask.fieldPaths=lec`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (res.status === 404) return false;
  if (res.ok) return true;
  throw new Error(`get failed: ${res.status} ${await res.text()}`);
}

// מזהה מסמך לזוג (הרצאה, סטודנט) — מבטיח רישום אחד לכל סטודנט בכל הרצאה
async function registrationId(lec, name) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(`${lec}|${name}`));
  return b64urlEncode(new Uint8Array(digest));
}

async function recordAttendance(env, { id, lec, name }) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getAccessToken(sa);
  const base = `projects/${sa.project_id}/databases/(default)/documents`;
  const now = new Date().toISOString();
  const regId = await registrationId(lec, name);

  const res = await fetch(
    `https://firestore.googleapis.com/v1/${base}:commit`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        writes: [
          {
            update: {
              name: `${base}/used/${id}`,
              fields: {
                lec: { stringValue: lec },
                usedAt: { timestampValue: now },
              },
            },
            currentDocument: { exists: false },
          },
          {
            update: {
              name: `${base}/attendance/${id}`,
              fields: {
                id: { stringValue: id },
                lec: { stringValue: lec },
                name: { stringValue: name },
                timestamp: { timestampValue: now },
              },
            },
            currentDocument: { exists: false },
          },
          {
            update: {
              name: `${base}/registered/${regId}`,
              fields: {
                lec: { stringValue: lec },
                name: { stringValue: name },
                id: { stringValue: id },
              },
            },
            currentDocument: { exists: false },
          },
        ],
      }),
    },
  );

  if (res.ok) return "ok";

  const err = await res.json().catch(() => ({}));
  const status = err?.error?.status;
  // precondition exists=false נכשל → אחד המסמכים כבר קיים.
  // Firestore לא אומר איזה, אז בודקים: אם הקוד נוצל → "used", אחרת הסטודנט כבר רשום.
  if (status === "ALREADY_EXISTS" || status === "FAILED_PRECONDITION") {
    return (await isUsed(env, id)) ? "used" : "already_registered";
  }
  throw new Error(`commit failed: ${res.status} ${JSON.stringify(err)}`);
}

// access token נשמר בזיכרון ה-isolate עד דקה לפני שפג
let cachedToken = null;

async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp - 60 > now) return cachedToken.token;

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: sa.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const unsigned = `${b64urlEncode(enc.encode(JSON.stringify(header)))}.${b64urlEncode(enc.encode(JSON.stringify(claims)))}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(unsigned));
  const jwt = `${unsigned}.${b64urlEncode(new Uint8Array(signature))}`;

  const res = await fetch(claims.aud, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) throw new Error(`token request failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  cachedToken = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

// ---------- helpers ----------

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function corsHeaders(request, env) {
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = request.headers.get("Origin") || "";
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  if (allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}
