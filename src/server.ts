import "dotenv/config";
import { randomBytes } from "node:crypto";
import path from "node:path";
import express, { type ErrorRequestHandler } from "express";
import { Pool } from "pg";
import {
  buildUserSearchStatement,
  hashPassword,
  isDemoTautologyPayload,
  verifyPassword,
} from "./security.js";

interface DemoUser {
  id: number;
  username: string;
  displayName: string;
  role: "admin" | "member";
  passwordHash: string;
}

interface PublicUser {
  id: number;
  username: string;
  displayName: string;
  role: "admin" | "member";
}

interface Modes {
  sqlInjectionEnabled: boolean;
  loginAttemptLimitDisabled: boolean;
  revealingAuthErrorsEnabled: boolean;
}

interface LoginSession {
  user: PublicUser;
  expiresAt: number;
}

const port = Number(process.env.PORT ?? "3000");
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT mora biti cijeli broj između 1 i 65535.");
}

const databaseUrl = process.env.DATABASE_URL;
const databasePassword = process.env.DB_PASSWORD;
if (databaseUrl && !new URL(databaseUrl).password) {
  throw new Error(
    "DATABASE_URL mora sadržavati PostgreSQL vjerodajnice ili koristite DB_* postavke.",
  );
}
if (!databaseUrl && !databasePassword) {
  throw new Error(
    "PostgreSQL lozinka nije postavljena. Kopirajte .env.example u .env i podesite DB_PASSWORD.",
  );
}

const pool = new Pool(
  databaseUrl
    ? { connectionString: databaseUrl, connectionTimeoutMillis: 5000 }
    : {
        host: process.env.DB_HOST ?? "localhost",
        port: Number(process.env.DB_PORT ?? "5432"),
        user: process.env.DB_USER ?? "postgres",
        password: databasePassword,
        database: process.env.DB_NAME ?? "web2_security_lab",
        connectionTimeoutMillis: 5000,
      },
);

const app = express();
const modes: Modes = {
  sqlInjectionEnabled: false,
  loginAttemptLimitDisabled: false,
  revealingAuthErrorsEnabled: false,
};
const sessions = new Map<string, LoginSession>();
const failedLoginAttempts = new Map<
  string,
  { failures: number; blockedUntil: number }
>();
const allowedHosts = new Set(["127.0.0.1", "localhost", "::1"]);
const maxFailedAttempts = 3;
const lockoutDurationMs = 30_000;

app.disable("x-powered-by");
app.use((req, res, next) => {
  const remoteAddress = req.socket.remoteAddress ?? "";
  const isLoopback =
    remoteAddress === "127.0.0.1" ||
    remoteAddress === "::1" ||
    remoteAddress.startsWith("::ffff:127.");

  if (!isLoopback || !allowedHosts.has(req.hostname)) {
    res.status(403).json({ error: "Aplikacija je dostupna samo lokalno." });
    return;
  }

  next();
});
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.resolve(import.meta.dirname, "../public")));

function publicUser(user: DemoUser): PublicUser {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role,
  };
}

function bearerToken(req: express.Request): string | undefined {
  const authorization = req.header("authorization");
  const match = authorization?.match(/^Bearer ([a-f0-9]{64})$/i);
  return match?.[1];
}

app.get("/api/modes", (_req, res) => {
  res.json(modes);
});

app.patch("/api/modes", (req, res) => {
  const updates = req.body as Partial<Modes> | undefined;
  const keys = updates ? Object.keys(updates) : [];
  const allowedKeys = new Set<keyof Modes>([
    "sqlInjectionEnabled",
    "loginAttemptLimitDisabled",
    "revealingAuthErrorsEnabled",
  ]);
  if (
    keys.length !== 1 ||
    !allowedKeys.has(keys[0] as keyof Modes) ||
    typeof updates?.[keys[0] as keyof Modes] !== "boolean"
  ) {
    res.status(400).json({ error: "Promijenite točno jednu valjanu postavku." });
    return;
  }

  Object.assign(modes, updates);
  res.json(modes);
});

app.post("/api/sql-search", async (req, res) => {
  const search = req.body?.search;
  if (typeof search !== "string" || search.length > 120) {
    res.status(400).json({ error: "Upit mora biti tekst do 120 znakova." });
    return;
  }

  const vulnerableDemo =
    modes.sqlInjectionEnabled && isDemoTautologyPayload(search);
  const statement = buildUserSearchStatement(search);
  const result = vulnerableDemo
    ? await pool.query<PublicUser>(
        `SELECT id, username, display_name AS "displayName", role
           FROM demo_users
          ORDER BY id`,
      )
    : await pool.query<PublicUser>(statement.text, statement.values);
  res.json({
    mode: modes.sqlInjectionEnabled ? "vulnerable" : "protected",
    demonstration: vulnerableDemo ? "tautology" : null,
    rows: result.rows,
  });
});

app.post("/api/login", async (req, res) => {
  const username = req.body?.username;
  const password = req.body?.password;
  if (
    typeof username !== "string" ||
    username.length === 0 ||
    username.length > 40 ||
    typeof password !== "string" ||
    password.length > 120
  ) {
    res.status(400).json({ error: "Unesite korisničko ime i zaporku." });
    return;
  }

  const attemptKeys = [
    `${req.ip}:address`,
    `${req.ip}:username:${username.toLowerCase()}`,
  ];
  const currentAttempts = attemptKeys.map((key) => failedLoginAttempts.get(key));
  const blockedAttempts = currentAttempts.find(
    (attempt) => attempt && attempt.blockedUntil > Date.now(),
  );
  if (
    !modes.loginAttemptLimitDisabled &&
    blockedAttempts
  ) {
    res.status(429).json({
      error: "Previše neuspješnih pokušaja. Pokušajte ponovno za 30 sekundi.",
      attempts: blockedAttempts.failures,
    });
    return;
  }

  const result = await pool.query<DemoUser>(
    `SELECT id, username, display_name AS "displayName", role,
            password_hash AS "passwordHash"
       FROM demo_users
      WHERE username = $1`,
    [username],
  );
  const user = result.rows[0];
  const passwordValid = !!user && verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    const attempts = Math.max(
      0,
      ...currentAttempts.map((attempt) => attempt?.failures ?? 0),
    ) + 1;
    for (const key of attemptKeys) {
      const failures = (failedLoginAttempts.get(key)?.failures ?? 0) + 1;
      const blockedUntil =
        !modes.loginAttemptLimitDisabled && failures >= maxFailedAttempts
          ? Date.now() + lockoutDurationMs
          : 0;
      failedLoginAttempts.set(key, { failures, blockedUntil });
    }
    const blockedUntil =
      !modes.loginAttemptLimitDisabled && attempts >= maxFailedAttempts;
    const errorMessage = modes.revealingAuthErrorsEnabled
      ? user
        ? "Zaporka nije ispravna."
        : "Korisničko ime nije pronađeno."
      : "Prijava nije uspješna.";
    res.status(blockedUntil ? 429 : 401).json({
      error: errorMessage,
      attempts,
      ...(blockedUntil ? { lockedForSeconds: lockoutDurationMs / 1000 } : {}),
    });
    return;
  }

  for (const key of attemptKeys) {
    failedLoginAttempts.delete(key);
  }
  const token = randomBytes(32).toString("hex");
  const profile = publicUser(user);
  sessions.set(token, {
    user: profile,
    expiresAt: Date.now() + 15 * 60 * 1000,
  });
  res.json({
    token,
    user: profile,
    mode: "protected",
    message: "Zaštićeni način: zaporka je provjerena.",
  });
});

app.post("/api/login/reset-demo", (_req, res) => {
  failedLoginAttempts.clear();
  res.json({ message: "Brojači pokušaja za demonstraciju su resetirani." });
});

app.get("/api/me", (req, res) => {
  const token = bearerToken(req);
  const session = token ? sessions.get(token) : undefined;
  if (
    token &&
    session &&
    session.expiresAt <= Date.now()
  ) {
    sessions.delete(token);
  }
  const activeSession = token ? sessions.get(token) : undefined;
  if (!activeSession) {
    res.status(401).json({ error: "Nema aktivne demonstracijske prijave." });
    return;
  }

  res.json(activeSession.user);
});

app.delete("/api/session", (req, res) => {
  const token = bearerToken(req);
  const session = token ? sessions.get(token) : undefined;
  if (token) {
    sessions.delete(token);
  }
  res.json({
    revoked: !!session,
    message: "Odjavljeni ste; poslužitelj je opozvao sjednicu.",
  });
});

const errorHandler: ErrorRequestHandler = (error, _req, res, next) => {
  console.error("Greška aplikacije:", error);
  if (res.headersSent) {
    next(error);
    return;
  }
  res.status(500).json({ error: "Došlo je do pogreške aplikacije." });
};
app.use(errorHandler);

async function initializeDatabase(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS demo_users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) NOT NULL UNIQUE,
      display_name VARCHAR(80) NOT NULL,
      role VARCHAR(10) NOT NULL CHECK (role IN ('admin', 'member')),
      password_hash VARCHAR(200) NOT NULL
    )
  `);

  const demoUsers = [
    {
      username: "demo-admin",
      displayName: "Administrator Demo",
      role: "admin" as const,
      password: "demo123",
    },
    {
      username: "demo-user",
      displayName: "Korisnik Demo",
      role: "member" as const,
      password: "demo123",
    },
  ];

  for (const user of demoUsers) {
    await pool.query(
      `INSERT INTO demo_users (username, display_name, role, password_hash)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING`,
      [user.username, user.displayName, user.role, hashPassword(user.password)],
    );
  }
}

async function start(): Promise<void> {
  await initializeDatabase();
  app.listen(port, "0.0.0.0", () => {
    console.log(`Servis postavljen http://0.0.0.0:${port}`);
  });
}

start().catch((error: unknown) => {
  console.error("Pokretanje aplikacije nije uspjelo:", error);
  process.exit(1);
});
