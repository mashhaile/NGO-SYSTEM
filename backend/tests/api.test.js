// API tests: start the real server against a separate,
// throwaway database ("ngo-system-test" on the local MongoDB),
// then exercise login, lockout, password reset, tenant
// isolation, error codes and search.
//
// Never runs against a remote database: if MONGO_URI in .env
// is not localhost, the tests are skipped.
//
// Run: npm test   (or: node --test tests/)

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const dotenv = require("dotenv");
const mongoose = require("mongoose");


const BACKEND = path.join(__dirname, "..");
const PORT = 5077;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;
const TEST_DB = "ngo-system-test";


// =====================================================
// TEST DATABASE
// =====================================================

const getTestUri = () => {

    const envFile = path.join(BACKEND, ".env");

    if (!fs.existsSync(envFile)) {
        return null;
    }

    const uri = dotenv.parse(fs.readFileSync(envFile)).MONGO_URI || "";

    const match =
        uri.match(/^mongodb:\/\/(?:[^@/]*@)?(localhost|127\.0\.0\.1)(:\d+)?\/?([^?]*)(\?.*)?$/);

    if (!match) {
        return null;
    }

    const [, host, port = "", , query = ""] = match;

    return `mongodb://${host}${port}/${TEST_DB}${query}`;

};


const TEST_URI = getTestUri();

const skip = TEST_URI
    ? false
    : "MONGO_URI is not a local database; API tests only run locally.";


const dropTestDatabase = async () => {

    const connection =
        await mongoose.createConnection(TEST_URI).asPromise();

    if (connection.name !== TEST_DB) {
        throw new Error(`Refusing to drop "${connection.name}"`);
    }

    await connection.dropDatabase();
    await connection.close();

};


const run = (args, env) =>
    new Promise((resolve, reject) => {
        const child = spawn(process.execPath, args, {
            cwd: BACKEND,
            env: { ...process.env, ...env },
            stdio: "ignore"
        });
        child.on("exit", code =>
            code === 0 ? resolve() : reject(new Error(`${args.join(" ")} exited ${code}`))
        );
    });


// =====================================================
// HTTP HELPER
// =====================================================

const api = async (method, url, { token, body, raw } = {}) => {

    const headers = {};

    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    if (body !== undefined || raw !== undefined) {
        headers["Content-Type"] = "application/json";
    }

    const response = await fetch(BASE + url, {
        method,
        headers,
        body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined
    });

    let data = null;
    try {
        data = await response.json();
    }
    catch {
        data = null;
    }

    return { status: response.status, data };

};


const login = (email, password) =>
    api("POST", "/auth/login", { body: { email, password } });


// =====================================================
// SERVER LIFECYCLE
// =====================================================

let server;

const state = {};


test.before(async () => {

    if (skip) return;

    await dropTestDatabase();

    // Plans are needed for sign-up (free trial)
    await run(["seeds/planseeder.js"], { MONGO_URI: TEST_URI });

    server = spawn(process.execPath, ["server.js"], {
        cwd: BACKEND,
        env: { ...process.env, PORT: String(PORT), MONGO_URI: TEST_URI, NODE_ENV: "test" },
        stdio: "ignore"
    });

    // Wait for the server (a non-auth route, so the auth rate limit is untouched)
    for (let i = 0; i < 60; i++) {
        try {
            await fetch(`${BASE}/health-check-not-a-route`);
            break;
        }
        catch {
            await new Promise(r => setTimeout(r, 500));
        }
    }

    // Two organizations, each with its own admin
    for (const key of ["A", "B"]) {

        const signup = await api("POST", "/organizations", {
            body: {
                name: `Test Org ${key}`,
                email: `org-${key.toLowerCase()}@test.local`,
                phone: `09110000${key === "A" ? "01" : "02"}`,
                country: "Ethiopia",
                admin: {
                    name: `Admin ${key}`,
                    email: `admin-${key.toLowerCase()}@test.local`,
                    password: `Admin${key}2026x`
                }
            }
        });

        assert.ok(signup.status < 300, `sign-up ${key}: ${signup.status} ${signup.data?.message}`);

    }

});


test.after(async () => {

    if (skip) return;

    server?.kill();

    await dropTestDatabase();

});


// =====================================================
// LOGIN
// =====================================================

test("login: email is case-insensitive, wrong password is 401", { skip }, async () => {

    const ok = await login("ADMIN-A@test.local", "AdminA2026x");
    assert.equal(ok.status, 200);
    assert.ok(ok.data.data.token);
    state.tokenA = ok.data.data.token;

    const wrong = await login("admin-a@test.local", "Nope12345");
    assert.equal(wrong.status, 401);

    const b = await login("admin-b@test.local", "AdminB2026x");
    assert.equal(b.status, 200);
    state.tokenB = b.data.data.token;
    state.adminBId = b.data.data.user.id;
    state.adminAId = ok.data.data.user.id;

});


test("users: weak passwords are rejected on create", { skip }, async () => {

    const weak = await api("POST", "/users", {
        token: state.tokenA,
        body: { name: "Weak User", email: "weak@test.local", password: "short", role: "data_entry" }
    });

    assert.equal(weak.status, 400);

    const created = await api("POST", "/users", {
        token: state.tokenA,
        body: { name: "Field Officer", email: "officer@test.local", password: "Officer2026x", role: "data_entry" }
    });

    assert.ok(created.status < 300, created.data?.message);
    state.officerId = created.data.data._id || created.data.data.id;

});


// =====================================================
// TENANT ISOLATION
// =====================================================

test("tenants: one organization cannot see another's records", { skip }, async () => {

    const created = await api("POST", "/programs", {
        token: state.tokenA,
        body: { name: "Org A Program", startDate: "2026-01-01" }
    });

    assert.ok(created.status < 300, created.data?.message);
    const programId = created.data.data._id;

    const own = await api("GET", `/programs/${programId}`, { token: state.tokenA });
    assert.equal(own.status, 200);

    const other = await api("GET", `/programs/${programId}`, { token: state.tokenB });
    assert.equal(other.status, 404);

    const list = await api("GET", "/programs", { token: state.tokenB });
    assert.equal(list.status, 200);
    assert.ok(!JSON.stringify(list.data).includes(programId));

});


test("tenants: an admin cannot reset another organization's user", { skip }, async () => {

    const res = await api("POST", `/users/${state.adminBId}/reset-password`, { token: state.tokenA });
    assert.equal(res.status, 404);

    const self = await api("POST", `/users/${state.adminAId}/reset-password`, { token: state.tokenA });
    assert.equal(self.status, 400);

});


// =====================================================
// ERROR CODES + SEARCH
// =====================================================

test("errors: bad id 400, unknown id 404, bad JSON 400, unknown route 404", { skip }, async () => {

    assert.equal((await api("GET", "/programs/not-an-id", { token: state.tokenA })).status, 400);
    assert.equal((await api("GET", "/programs/6aa686b69a8f0dadc14e0000", { token: state.tokenA })).status, 404);
    assert.equal((await api("POST", "/donors", { token: state.tokenA, raw: "{bad" })).status, 400);
    assert.equal((await api("GET", "/no-such-route", { token: state.tokenA })).status, 404);

});


test("search: regex characters do not break the query", { skip }, async () => {

    for (const text of ["((", "[a", ".*", "a+b"]) {
        const res = await api("GET", `/programs?search=${encodeURIComponent(text)}`, { token: state.tokenA });
        assert.equal(res.status, 200, text);
    }

    const literal = await api("GET", `/programs?search=${encodeURIComponent(".*")}`, { token: state.tokenA });
    assert.equal((literal.data.data || []).length, 0, "'.*' must not match everything");

});


// =====================================================
// LOCKOUT + ADMIN RESET + FORCED CHANGE
// =====================================================

test("lockout: 5 wrong passwords lock the account (423)", { skip }, async () => {

    const first = await login("officer@test.local", "Officer2026x");
    assert.equal(first.status, 200);
    state.officerToken = first.data.data.token;

    const statuses = [];
    for (let i = 0; i < 5; i++) {
        statuses.push((await login("officer@test.local", "Wrong2026x")).status);
    }

    assert.deepEqual(statuses, [401, 401, 401, 401, 423]);

    // Even the right password is refused while locked
    assert.equal((await login("officer@test.local", "Officer2026x")).status, 423);

});


test("reset: temp password, old sessions end, change is forced", { skip }, async () => {

    const reset = await api("POST", `/users/${state.officerId}/reset-password`, { token: state.tokenA });
    assert.equal(reset.status, 200);

    const temp = reset.data.data.temporaryPassword;
    assert.equal(temp.length, 12);

    // The session from before the reset has ended
    const old = await api("GET", "/programs", { token: state.officerToken });
    assert.equal(old.status, 401);
    assert.equal(old.data.code, "PASSWORD_CHANGED");

    // The reset also cleared the lockout
    const tempLogin = await login("officer@test.local", temp);
    assert.equal(tempLogin.status, 200);
    assert.equal(tempLogin.data.data.user.mustChangePassword, true);
    const tempToken = tempLogin.data.data.token;

    // Nothing else works until the password is changed
    const blocked = await api("GET", "/programs", { token: tempToken });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.data.code, "PASSWORD_CHANGE_REQUIRED");

    const weak = await api("POST", "/auth/change-password", {
        token: tempToken,
        body: { currentPassword: temp, newPassword: "short" }
    });
    assert.equal(weak.status, 400);

    const changed = await api("POST", "/auth/change-password", {
        token: tempToken,
        body: { currentPassword: temp, newPassword: "Officer2027x" }
    });
    assert.equal(changed.status, 200);

    const after = await api("GET", "/programs", { token: changed.data.data.token });
    assert.equal(after.status, 200);

    assert.equal((await login("officer@test.local", temp)).status, 401);

});
