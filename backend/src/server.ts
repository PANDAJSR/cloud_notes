import cors from "cors";
import express from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

type StoredNote = {
  payload: string | null;
  updatedAt: string | null;
};

type Session = {
  login: string;
  avatarUrl: string | null;
  createdAt: number;
};

type GitHubUser = {
  login?: string;
  avatar_url?: string | null;
};

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const defaultDataFile = path.resolve(__dirname, "../data/note.json");
const dataFile = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : defaultDataFile;
const port = Number(process.env.PORT ?? 1873);
const publicBaseUrl = (process.env.PUBLIC_BASE_URL ?? "http://localhost:5173").replace(
  /\/$/,
  ""
);
const notesPath = process.env.NOTES_PATH ?? "/notes/";
const githubClientId = process.env.GITHUB_CLIENT_ID;
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET;
const allowedLogins = new Set(
  (process.env.GITHUB_ALLOWED_LOGINS ?? "")
    .split(",")
    .map((login) => login.trim().toLowerCase())
    .filter(Boolean)
);
const authConfigured =
  Boolean(githubClientId && githubClientSecret) && allowedLogins.size > 0;
const sessions = new Map<string, Session>();

const app = express();

app.set("trust proxy", true);
app.use(cors({ credentials: true, origin: true }));
app.use(express.json({ limit: "1mb" }));

async function readNote(): Promise<StoredNote> {
  try {
    const raw = await readFile(dataFile, "utf8");
    const parsed = JSON.parse(raw) as StoredNote;

    return {
      payload: typeof parsed.payload === "string" ? parsed.payload : null,
      updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : null
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      return { payload: null, updatedAt: null };
    }

    throw error;
  }
}

async function writeNote(payload: string): Promise<StoredNote> {
  const nextNote = {
    payload,
    updatedAt: new Date().toISOString()
  };
  const tempFile = `${dataFile}.${process.pid}.tmp`;

  await mkdir(path.dirname(dataFile), { recursive: true });
  await writeFile(tempFile, JSON.stringify(nextNote, null, 2), "utf8");
  await rename(tempFile, dataFile);

  return nextNote;
}

function readCookies(request: express.Request): Record<string, string> {
  const cookieHeader = request.headers.cookie;
  if (!cookieHeader) {
    return {};
  }

  return Object.fromEntries(
    cookieHeader.split(";").flatMap((cookie) => {
      const separatorIndex = cookie.indexOf("=");
      if (separatorIndex === -1) {
        return [];
      }

      const name = cookie.slice(0, separatorIndex).trim();
      const value = cookie.slice(separatorIndex + 1).trim();
      return [[name, decodeURIComponent(value)]];
    })
  );
}

function createCookie(
  name: string,
  value: string,
  options: { httpOnly?: boolean; maxAgeSeconds?: number } = {}
): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "SameSite=Lax"
  ];

  if (options.httpOnly ?? true) {
    parts.push("HttpOnly");
  }

  if (publicBaseUrl.startsWith("https://")) {
    parts.push("Secure");
  }

  if (typeof options.maxAgeSeconds === "number") {
    parts.push(`Max-Age=${options.maxAgeSeconds}`);
  }

  return parts.join("; ");
}

function clearCookie(name: string): string {
  return createCookie(name, "", { maxAgeSeconds: 0 });
}

function createToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);

  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function getSession(request: express.Request): Session | null {
  const sessionId = readCookies(request).cloud_notes_session;
  if (!sessionId) {
    return null;
  }

  return sessions.get(sessionId) ?? null;
}

function requireAuth(
  request: express.Request,
  response: express.Response,
  next: express.NextFunction
) {
  if (!authConfigured) {
    response.status(503).json({ error: "github oauth is not configured" });
    return;
  }

  const session = getSession(request);
  if (!session) {
    response.status(401).json({ error: "login required" });
    return;
  }

  next();
}

app.get("/api/health", (_request, response) => {
  response.json({ ok: true });
});

app.get("/api/auth/me", (request, response) => {
  const session = getSession(request);

  response.json({
    configured: authConfigured,
    authenticated: Boolean(session),
    user: session
      ? {
          login: session.login,
          avatarUrl: session.avatarUrl
        }
      : null
  });
});

app.get("/api/auth/github", (_request, response) => {
  if (!authConfigured || !githubClientId) {
    response.status(503).json({ error: "github oauth is not configured" });
    return;
  }

  const state = createToken();
  const callbackUrl = `${publicBaseUrl}/api/auth/github/callback`;
  const authorizeUrl = new URL("https://github.com/login/oauth/authorize");

  authorizeUrl.searchParams.set("client_id", githubClientId);
  authorizeUrl.searchParams.set("redirect_uri", callbackUrl);
  authorizeUrl.searchParams.set("scope", "read:user");
  authorizeUrl.searchParams.set("state", state);

  response.setHeader("Set-Cookie", createCookie("cloud_notes_oauth_state", state, {
    maxAgeSeconds: 600
  }));
  response.redirect(authorizeUrl.toString());
});

app.get("/api/auth/github/callback", async (request, response, next) => {
  try {
    if (!authConfigured || !githubClientId || !githubClientSecret) {
      response.status(503).json({ error: "github oauth is not configured" });
      return;
    }

    const code = typeof request.query.code === "string" ? request.query.code : "";
    const state = typeof request.query.state === "string" ? request.query.state : "";
    const expectedState = readCookies(request).cloud_notes_oauth_state;

    if (!code || !state || !expectedState || !safeEqual(state, expectedState)) {
      response.status(400).send("Invalid OAuth state");
      return;
    }

    const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: githubClientId,
        client_secret: githubClientSecret,
        code,
        redirect_uri: `${publicBaseUrl}/api/auth/github/callback`
      })
    });

    if (!tokenResponse.ok) {
      throw new Error(`GitHub token exchange failed: ${tokenResponse.status}`);
    }

    const tokenPayload = (await tokenResponse.json()) as {
      access_token?: string;
      error?: string;
    };

    if (!tokenPayload.access_token) {
      throw new Error(tokenPayload.error ?? "GitHub token exchange failed");
    }

    const userResponse = await fetch("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${tokenPayload.access_token}`,
        "User-Agent": "cloud-notes"
      }
    });

    if (!userResponse.ok) {
      throw new Error(`GitHub user lookup failed: ${userResponse.status}`);
    }

    const user = (await userResponse.json()) as GitHubUser;
    const login = user.login?.toLowerCase();

    if (!login || !allowedLogins.has(login)) {
      response
        .status(403)
        .setHeader("Set-Cookie", clearCookie("cloud_notes_oauth_state"))
        .send("This GitHub account is not allowed.");
      return;
    }

    const sessionId = createToken();
    sessions.set(sessionId, {
      login,
      avatarUrl: user.avatar_url ?? null,
      createdAt: Date.now()
    });

    response.setHeader("Set-Cookie", [
      clearCookie("cloud_notes_oauth_state"),
      createCookie("cloud_notes_session", sessionId, { maxAgeSeconds: 60 * 60 * 24 * 30 })
    ]);
    response.redirect(notesPath);
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/logout", (request, response) => {
  const sessionId = readCookies(request).cloud_notes_session;
  if (sessionId) {
    sessions.delete(sessionId);
  }

  response.setHeader("Set-Cookie", clearCookie("cloud_notes_session"));
  response.json({ ok: true });
});

app.get("/api/note", requireAuth, async (_request, response, next) => {
  try {
    response.json(await readNote());
  } catch (error) {
    next(error);
  }
});

app.put("/api/note", requireAuth, async (request, response, next) => {
  try {
    const payload = request.body?.payload;

    if (typeof payload !== "string" || payload.length > 750_000) {
      response.status(400).json({ error: "payload must be a string under 750KB" });
      return;
    }

    response.json(await writeNote(payload));
  } catch (error) {
    next(error);
  }
});

app.use(
  (
    error: unknown,
    _request: express.Request,
    response: express.Response,
    _next: express.NextFunction
  ) => {
    console.error(error);
    response.status(500).json({ error: "internal server error" });
  }
);

app.listen(port, "0.0.0.0", () => {
  console.log(`cloud-notes backend listening on ${port}`);
});
