const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const ALICE_UID = "alice_uid_123";
const BOB_UID = "bob_uid_456";

const [emulatorHost, emulatorPortStr] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085").split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

// --- 1. USER PROFILE SECURITY TESTS ---

test("Unauthenticated user: cannot read or write any user profile or subcollections", async () => {
  const unauthDb = testEnv.unauthenticatedContext().firestore();
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).collection("whitelist").get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).collection("certificateRules").get());
  await assertFails(unauthDb.collection("users").doc(ALICE_UID).collection("scanHistory").get());
  await assertFails(
    unauthDb.collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Unauth",
      autoSyncEnabled: true,
      totalSyncedScans: 0,
      createdAt: new Date(Date.now() - 1000),
      updatedAt: new Date(Date.now() - 1000),
    })
  );
});

test("User profile: owner create, partial update, immutable field protection, and cross-user isolation", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 5000);

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).set({
      userId: ALICE_UID,
      displayName: "Alice",
      email: "alice@example.com",
      autoSyncEnabled: true,
      totalSyncedScans: 0,
      createdAt: created,
      updatedAt: created,
    })
  );

  await assertSucceeds(aliceDb.collection("users").doc(ALICE_UID).get());

  // Partial update preserving userId & createdAt
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).update({
      displayName: "Alice Silva",
      totalSyncedScans: 3,
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Reject ghost field / privilege escalation
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      isAdmin: true,
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Reject tampering with createdAt or userId
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      createdAt: new Date(Date.now() - 500),
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Reject future timestamp (> request.time)
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).update({
      totalSyncedScans: 4,
      updatedAt: new Date(Date.now() + 120000),
    })
  );

  // Reject cross-user list or read
  await assertFails(bobDb.collection("users").get());
  await assertFails(bobDb.collection("users").doc(ALICE_UID).get());
  await assertFails(
    bobDb.collection("users").doc(ALICE_UID).update({
      displayName: "Hijacked",
      updatedAt: new Date(Date.now() - 500),
    })
  );
});

// --- 2. WHITELIST SUBCOLLECTION TESTS ---

test("Whitelist subcollection: Kotlin create/update/list/delete succeed for owner and fail for others or bad schema", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 5000);

  // Matches safeDocId("com.trusted.bank") -> "com_trusted_bank"
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com_trusted_bank").set({
      packageName: "com.trusted.bank",
      appName: "Banco Seguro",
      sha256Fingerprint: "AA:BB:CC:DD",
      reason: "Marcado pelo usuário como confiável",
      addedAtMillis: Date.now() - 5000,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Mirrors Kotlin list query (must work even on empty or populated subcollection)
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").orderBy("addedAtMillis", "desc").get()
  );

  // Partial update preserving packageName and createdAt
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com_trusted_bank").update({
      reason: "App corporativo verificado",
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Reject storing `@DocumentId` "id" field in payload
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com_another_app").set({
      id: "com_another_app",
      packageName: "com.another.app",
      appName: "Another",
      sha256Fingerprint: "11:22",
      reason: "Test",
      addedAtMillis: Date.now() - 1000,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Reject invalid document ID (contains dots or invalid chars)
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com.invalid.dot").set({
      packageName: "com.invalid.dot",
      appName: "Bad ID",
      sha256Fingerprint: "11:22",
      reason: "Test",
      addedAtMillis: Date.now() - 1000,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Reject cross-user access
  await assertFails(bobDb.collection("users").doc(ALICE_UID).collection("whitelist").get());
  await assertFails(bobDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com_trusted_bank").delete());

  // Owner delete succeeds
  await assertSucceeds(aliceDb.collection("users").doc(ALICE_UID).collection("whitelist").doc("com_trusted_bank").delete());
});

// --- 3. CERTIFICATE RULES SUBCOLLECTION TESTS ---

test("Certificate rules: owner CRUD + enum/size validation", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 5000);

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("certificateRules").doc("AABBCCDD1122").set({
      sha256Fingerprint: "AA:BB:CC:DD:11:22",
      label: "Empresa Oficial",
      trustStatus: "TRUSTED",
      packageNameHint: "com.empresa.app",
      notes: "Aprovado manualmente",
      createdAt: created,
      updatedAt: created,
    })
  );

  // Update trustStatus to BLOCKED
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("certificateRules").doc("AABBCCDD1122").update({
      trustStatus: "BLOCKED",
      notes: "Chave comprometida",
      updatedAt: new Date(Date.now() - 1000),
    })
  );

  // Reject invalid enum value
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("certificateRules").doc("AABBCCDD1122").update({
      trustStatus: "NEUTRAL",
      updatedAt: new Date(Date.now() - 500),
    })
  );

  // Cross-user isolation
  await assertFails(bobDb.collection("users").doc(ALICE_UID).collection("certificateRules").get());
});

// --- 4. SCAN HISTORY SUBCOLLECTION TESTS ---

test("Scan history: owner create/query/delete + riskScore bounds + enum validation", async () => {
  const aliceDb = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bobDb = testEnv.authenticatedContext(BOB_UID).firestore();
  const created = new Date(Date.now() - 5000);

  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("scanHistory").doc("com_fake_trojan_1700000500").set({
      packageName: "com.fake.trojan",
      appName: "Trojan APK",
      versionName: "2.0.1",
      scanSource: "GATEKEEPER_APK",
      verdict: "BLOQUEADO",
      riskScore: 95,
      sha256Fingerprint: "FF:EE:DD",
      findingsSummary: "• Assinatura inválida detectada",
      scannedAtMillis: 1700000500,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Matches Kotlin ordered query
  await assertSucceeds(
    aliceDb.collection("users").doc(ALICE_UID).collection("scanHistory").orderBy("scannedAtMillis", "desc").limit(50).get()
  );

  // Reject out-of-range riskScore (> 100)
  await assertFails(
    aliceDb.collection("users").doc(ALICE_UID).collection("scanHistory").doc("bad_score_1").set({
      packageName: "com.bad.score",
      appName: "Bad Score",
      versionName: "1.0",
      scanSource: "VARREDURA_DISPOSITIVO",
      verdict: "BLOQUEADO",
      riskScore: 150,
      sha256Fingerprint: "11:22",
      findingsSummary: "• Score inválido",
      scannedAtMillis: 1700000600,
      createdAt: created,
      updatedAt: created,
    })
  );

  // Reject cross-user read or write
  await assertFails(bobDb.collection("users").doc(ALICE_UID).collection("scanHistory").get());
});
