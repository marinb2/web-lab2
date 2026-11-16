import assert from "node:assert/strict";
import test from "node:test";
import {
  buildUserSearchStatement,
  hashPassword,
  isDemoTautologyPayload,
  verifyPassword,
} from "../src/security.js";

test("pretraga uvijek šalje unos kao parametar, uključujući ranjivi demo način", () => {
  const search = "' OR '1'='1' -- ";
  const statement = buildUserSearchStatement(search);

  assert.match(statement.text, /ILIKE \$1/);
  assert.deepEqual(statement.values, [`%${search}%`]);
  assert.equal(statement.text.includes(search), false);
});

test("prepoznaje samo fiksnu sintetičku tautologiju za sigurnu demonstraciju", () => {
  assert.equal(isDemoTautologyPayload("' OR '1'='1' -- "), true);
  assert.equal(isDemoTautologyPayload("' or '1' = '1' --"), true);
  assert.equal(isDemoTautologyPayload("marin"), false);
  assert.equal(isDemoTautologyPayload("' OR '1'='1' UNION SELECT password --"), false);
});

test("provjera zaporke prihvaća ispravnu i odbija pogrešnu zaporku", () => {
  const encodedHash = hashPassword("demo123", Buffer.alloc(16, 7));

  assert.equal(verifyPassword("demo123", encodedHash), true);
  assert.equal(verifyPassword("pogresna", encodedHash), false);
  assert.equal(verifyPassword("demo123", "neispravan-format"), false);
});

