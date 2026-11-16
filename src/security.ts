import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const passwordHashBytes = 64;

export interface SearchStatement {
  text: string;
  values: string[];
}

export function buildUserSearchStatement(search: string): SearchStatement {
  const columns =
    'SELECT id, username, display_name AS "displayName", role FROM demo_users WHERE username ILIKE';

  return {
    text: `${columns} $1 ORDER BY id`,
    values: [`%${search}%`],
  };
}

export function isDemoTautologyPayload(search: string): boolean {
  return /^\s*'\s*OR\s*'1'\s*=\s*'1'\s*--\s*$/i.test(search);
}

export function hashPassword(
  password: string,
  salt: Buffer = randomBytes(16),
): string {
  const hash = scryptSync(password, salt, passwordHashBytes).toString("hex");
  return `${salt.toString("hex")}:${hash}`;
}

export function verifyPassword(password: string, encodedHash: string): boolean {
  const match = /^([a-f0-9]{32}):([a-f0-9]{128})$/i.exec(encodedHash);
  if (!match) {
    return false;
  }

  const salt = Buffer.from(match[1], "hex");
  const expectedHash = Buffer.from(match[2], "hex");
  const actualHash = scryptSync(password, salt, passwordHashBytes);

  return timingSafeEqual(actualHash, expectedHash);
}
