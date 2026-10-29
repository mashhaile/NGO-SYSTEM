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

    // No plan seeding here on purpose: the server must
    // create the default plans itself on a fresh database.

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

    // Startup creates the default plans shortly after connecting
    state.db = await mongoose.createConnection(TEST_URI).asPromise();

    for (let i = 0; i < 60; i++) {
        if (await state.db.collection("plans").countDocuments() >= 4) break;
        await new Promise(r => setTimeout(r, 500));
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

    await state.db?.close();

    await dropTestDatabase();

});


// =====================================================
// FRESH DATABASE SETUP
// =====================================================

test("startup: default plans are created on a fresh database", { skip }, async () => {

    const codes =
        (await state.db.collection("plans").find().toArray()).map(plan => plan.code).sort();

    assert.deepEqual(codes, ["ENTERPRISE", "FREE", "PRO", "STARTER"]);

});


test("sign-up: a new organization gets units and common lookups", { skip }, async () => {

    const organization =
        await state.db.collection("organizations").findOne({ email: "org-a@test.local" });

    const counts = {};

    for (const row of await state.db.collection("lookups").find({ organization: organization._id }).toArray()) {
        counts[row.category] = (counts[row.category] || 0) + 1;
    }

    for (const category of [
        "Gender", "EducationLevel", "Occupation", "MaritalStatus", "DisabilityType", "VulnerableGroup",
        "EnterpriseType", "OwnershipType", "BusinessSector",
        "ServiceCategory", "ServiceType", "Unit"
    ]) {
        assert.ok(counts[category] > 0, `${category} was not seeded`);
    }

    assert.equal(counts.Gender, 2);

    // Service types point at a real category and real units
    const schoolFees =
        await state.db.collection("lookups").findOne({ organization: organization._id, category: "ServiceType", value: "School Fees" });

    const parent =
        await state.db.collection("lookups").findOne({ _id: schoolFees.parentLookup });

    assert.equal(parent.value, "Education");

    const etb =
        await state.db.collection("lookups").findOne({ organization: organization._id, category: "Unit", code: "ETB" });
    assert.ok(schoolFees.allowedUnits.some(id => String(id) === String(etb._id)), "School Fees is paid in ETB");

    // One unit per meaning: no Kilogram / Litre / Pieces / Birr duplicates
    const units =
        await state.db.collection("lookups").find({ organization: organization._id, category: "Unit" }).toArray();
    for (const duplicate of ["Kilogram", "Litre", "Pieces", "Birr", "Money", "Cash", "Amount"]) {
        assert.ok(!units.some(unit => unit.value === duplicate), `${duplicate} should not be seeded`);
    }

    // Trainings: each participant takes part in the whole quantity
    const training =
        await state.db.collection("lookups").findOne({ organization: organization._id, category: "ServiceType", value: "Business Skills Training" });
    assert.equal(training.allocationBehavior, "PARTICIPATION");

});


test("sign-up: works when the organization counter is behind existing codes", { skip }, async () => {

    // Organizations created before the counter existed (live) made
    // every new sign-up fail with a duplicate organizationCode.
    await state.db.collection("counters").updateOne(
        { module: "Organization", organization: null },
        { $set: { sequence: 0 } }
    );

    const signup = await api("POST", "/organizations", {
        body: {
            name: "Counter Behind Org",
            email: "org-counter@test.local",
            phone: "0911000099",
            country: "Ethiopia",
            admin: { name: "Counter Admin", email: "admin-counter@test.local", password: "Counter2026x" }
        }
    });
    assert.ok(signup.status < 300, `${signup.status} ${signup.data?.message}`);

    const created = await state.db.collection("organizations").findOne({ email: "org-counter@test.local" });
    const others = await state.db.collection("organizations").countDocuments({ organizationCode: created.organizationCode });
    assert.equal(others, 1, "the code is unique");

});


test("super admin: a created organization also gets common lookups", { skip }, async () => {

    await run(
        ["scripts/createSuperAdmin.js", "sa@test.local", "Test Super Admin", "SuperTest2026x"],
        { MONGO_URI: TEST_URI }
    );

    const sa = await login("sa@test.local", "SuperTest2026x");
    assert.equal(sa.status, 200);

    const created = await api("POST", "/admin/organizations", {
        token: sa.data.data.token,
        body: {
            name: "Test Org C",
            email: "org-c@test.local",
            phone: "0911000003",
            country: "Ethiopia",
            adminName: "Admin C",
            adminEmail: "admin-c@test.local",
            adminPassword: "AdminC2026x"
        }
    });

    assert.ok(created.status < 300, `${created.status} ${created.data?.message}`);

    const organization =
        await state.db.collection("organizations").findOne({ email: "org-c@test.local" });

    const categories =
        await state.db.collection("lookups").distinct("category", { organization: organization._id });

    // 12 + Project Type
    assert.equal(categories.length, 13, `got: ${categories.join(", ")}`);

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
        body: { name: "Field Officer", email: "officer@test.local", password: "Officer2026x", role: "data_entry", mustChangePassword: false }
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
// BUDGETS
// =====================================================

const yearly = (pairs) =>
    Object.entries(pairs).map(([fiscalYear, amount]) => ({ fiscalYear: Number(fiscalYear), amount }));


test("budgets: program envelope, project allocation and limits", { skip }, async () => {

    const token = state.tokenA;

    const program = await api("POST", "/programs", { token, body: { name: "Budget Test Program", startDate: "2026-01-01" } });
    assert.ok(program.status < 300, program.data?.message);
    const programId = program.data.data._id;
    state.budgetProgramId = programId;

    const project = async (name) => {
        const res = await api("POST", "/projects", {
            token,
            body: { program: programId, name, startDate: "2026-01-01", endDate: "2028-12-31" }
        });
        assert.ok(res.status < 300, res.data?.message);
        return res.data.data._id;
    };

    state.projectOne = await project("Budget Project One");
    const projectTwo = await project("Budget Project Two");

    // Program envelope: 1,000,000 a year for 2026-2028
    const envelope = await api("POST", "/budgets", {
        token,
        body: {
            level: "program", name: "Program Budget 2026-2028", program: programId,
            startYear: 2026, endYear: 2028, yearlyAmounts: yearly({ 2026: 1000000, 2027: 1000000, 2028: 1000000 })
        }
    });
    assert.equal(envelope.status, 201, envelope.data?.message);
    assert.equal(envelope.data.data.totalAmount, 3000000);
    assert.equal(envelope.data.data.status, "Draft");
    state.envelopeId = envelope.data.data._id;

    // Only one budget per program
    const duplicate = await api("POST", "/budgets", {
        token,
        body: { level: "program", name: "Second Program Budget", program: programId, startYear: 2026, endYear: 2026 }
    });
    assert.equal(duplicate.status, 409);

    // Amounts outside the period are refused
    const outside = await api("POST", "/budgets", {
        token,
        body: {
            level: "project", name: "Out of range", project: projectTwo,
            startYear: 2026, endYear: 2026,
            lines: [{ category: "Personnel", amounts: yearly({ 2027: 5 }) }]
        }
    });
    assert.equal(outside.status, 400);

    // Project one: 600,000 in 2026 (lines are summed server-side)
    const one = await api("POST", "/budgets", {
        token,
        body: {
            level: "project", name: "Project One Budget", project: state.projectOne,
            startYear: 2026, endYear: 2027,
            lines: [
                { category: "Personnel", description: "Coordinator", amounts: yearly({ 2026: 400000, 2027: 400000 }) },
                { category: "Training & Workshops", amounts: yearly({ 2026: 200000, 2027: 100000 }) }
            ]
        }
    });
    assert.equal(one.status, 201, one.data?.message);
    assert.equal(one.data.data.totalAmount, 1100000);
    assert.equal(String(one.data.data.program._id), programId, "program comes from the project");
    state.budgetOneId = one.data.data._id;

    assert.equal((await api("POST", `/budgets/${state.budgetOneId}/submit`, { token })).status, 200);

    // Project two asks for 500,000 in 2026: only 400,000 left
    const two = await api("POST", "/budgets", {
        token,
        body: {
            level: "project", name: "Project Two Budget", project: projectTwo,
            startYear: 2026, endYear: 2026,
            lines: [{ category: "Supplies & Materials", amounts: yearly({ 2026: 500000 }) }]
        }
    });
    assert.equal(two.status, 201);
    state.budgetTwoId = two.data.data._id;

    const over = await api("POST", `/budgets/${two.data.data._id}/submit`, { token });
    assert.equal(over.status, 400);
    assert.match(over.data.message, /400,000/);

    // A different currency than the program budget is refused
    await api("PUT", `/budgets/${two.data.data._id}`, {
        token,
        body: { currency: "USD", lines: [{ category: "Supplies & Materials", amounts: yearly({ 2026: 100 }) }] }
    });
    const currency = await api("POST", `/budgets/${two.data.data._id}/submit`, { token });
    assert.equal(currency.status, 400);
    assert.match(currency.data.message, /ETB/);

    // Program summary shows the allocation per year
    const details = await api("GET", `/budgets/${state.envelopeId}`, { token });
    const year2026 = details.data.data.summary.allocation.years.find(item => item.fiscalYear === 2026);
    // The USD draft has no exchange rate yet, so it is not added to
    // ETB figures (never 600,000 ETB + 100 USD)
    assert.equal(year2026.allocated, 600000);
    assert.equal(year2026.unallocated, 400000);

    // Fiscal-year filter
    const in2028 = await api("GET", "/budgets?fiscalYear=2028", { token });
    assert.deepEqual(in2028.data.data.map(budget => budget.budgetCode), [envelope.data.data.budgetCode]);

});


test("budgets: finance officer approves; approved budgets are locked", { skip }, async () => {

    // The Free plan allows 2 users (admin + officer already); give
    // organization A room for a third, as a plan upgrade would.
    const orgA = await state.db.collection("organizations").findOne({ email: "org-a@test.local" });
    await state.db.collection("subscriptions").updateMany(
        { organization: orgA._id },
        { $set: { "planSnapshot.limits.users": 10 } }
    );

    const created = await api("POST", "/users", {
        token: state.tokenA,
        body: { name: "Finance Officer", email: "finance@test.local", password: "Finance2026x", role: "finance_officer", mustChangePassword: false }
    });
    assert.ok(created.status < 300, created.data?.message);

    const finance = (await login("finance@test.local", "Finance2026x")).data.data.token;
    state.financeToken = finance;

    // Return needs a comment
    assert.equal((await api("POST", `/budgets/${state.budgetOneId}/return`, { token: finance, body: {} })).status, 400);

    // The program budget (the ceiling) must be approved first
    const tooEarly = await api("POST", `/budgets/${state.budgetOneId}/approve`, { token: finance, body: {} });
    assert.equal(tooEarly.status, 400);
    assert.match(tooEarly.data.message, /program budget/i);

    // The USD draft would block the ETB program budget; remove it
    assert.equal((await api("DELETE", `/budgets/${state.budgetTwoId}`, { token: finance })).status, 200);

    assert.equal((await api("POST", `/budgets/${state.envelopeId}/submit`, { token: finance })).status, 200);
    assert.equal((await api("POST", `/budgets/${state.envelopeId}/approve`, { token: finance, body: {} })).status, 200);

    const approved = await api("POST", `/budgets/${state.budgetOneId}/approve`, { token: finance, body: { comment: "OK" } });
    assert.equal(approved.status, 200, approved.data?.message);
    assert.equal(approved.data.data.status, "Approved");

    // Locked
    const edit = await api("PUT", `/budgets/${state.budgetOneId}`, { token: finance, body: { name: "Changed name" } });
    assert.equal(edit.status, 409);

    // Approving twice is refused
    assert.equal((await api("POST", `/budgets/${state.budgetOneId}/approve`, { token: finance, body: {} })).status, 409);

    // Data entry can read budgets but not create them
    const officer = (await login("officer@test.local", "Officer2026x")).data.data.token;
    state.dataEntryToken = officer;
    assert.equal((await api("GET", "/budgets", { token: officer })).status, 200);
    assert.equal(
        (await api("POST", "/budgets", {
            token: officer,
            body: { level: "program", name: "Not allowed", program: state.adminAId, startYear: 2026, endYear: 2026 }
        })).status,
        403
    );

    // Other organizations cannot see it
    assert.equal((await api("GET", `/budgets/${state.budgetOneId}`, { token: state.tokenB })).status, 404);

});


// =====================================================
// EXPENSES
// =====================================================
//
// Budget one (approved): Personnel 2026 = 400,000,
// Training & Workshops 2026 = 200,000.
//
// =====================================================

const lineOf = async (token, budgetId, category) => {
    const budget = (await api("GET", `/budgets/${budgetId}`, { token })).data.data;
    return { budget, line: budget.summary.lines.find(line => line.category === category) };
};

const newExpense = (token, body) =>
    api("POST", "/expenses", {
        token,
        body: { budget: state.budgetOneId, expenseDate: "2026-03-15", paymentMethod: "Bank Transfer", ...body }
    });


test("expenses: recorded on approved budget lines; spent counts approved only", { skip }, async () => {

    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const { line: personnel } = await lineOf(de, state.budgetOneId, "Personnel");

    // Program budgets and unapproved budgets cannot be charged
    assert.equal((await newExpense(de, { budget: state.envelopeId, budgetLine: personnel._id, description: "x x x", amount: 10 })).status, 404);

    // The date must fall inside the budget period
    assert.equal((await newExpense(de, { budgetLine: personnel._id, expenseDate: "2030-01-10", description: "Out of period", amount: 10 })).status, 400);

    const first = await newExpense(de, { budgetLine: personnel._id, description: "Coordinator salary, March", payee: "Coordinator", amount: 150000 });
    assert.equal(first.status, 201, first.data?.message);
    assert.equal(first.data.data.status, "Draft");
    assert.equal(first.data.data.fiscalYear, 2026);
    assert.equal(first.data.data.category, "Personnel");
    state.expenseOne = first.data.data._id;

    // Draft: pending, not spent
    let { line } = await lineOf(de, state.budgetOneId, "Personnel");
    assert.equal(line.spent, 0);
    assert.equal(line.pending, 150000);

    assert.equal((await api("POST", `/expenses/${state.expenseOne}/submit`, { token: de })).status, 200);

    // Data entry cannot approve
    assert.equal((await api("POST", `/expenses/${state.expenseOne}/approve`, { token: de, body: {} })).status, 403);

    const approved = await api("POST", `/expenses/${state.expenseOne}/approve`, { token: fin, body: {} });
    assert.equal(approved.status, 200, approved.data?.message);
    assert.equal(approved.data.data.status, "Approved");
    assert.equal(approved.data.data.line.remainingAfter, 250000);

    ({ line } = await lineOf(de, state.budgetOneId, "Personnel"));
    assert.equal(line.spent, 150000);
    assert.equal(line.pending, 0);
    assert.equal(line.amounts.find(item => item.fiscalYear === 2026).remaining, 250000);

    // Approved expenses are locked
    assert.equal((await api("PUT", `/expenses/${state.expenseOne}`, { token: fin, body: { amount: 1 } })).status, 409);
    assert.equal((await api("DELETE", `/expenses/${state.expenseOne}`, { token: fin })).status, 409);

});


test("expenses: over budget needs a deliberate approval with a reason", { skip }, async () => {

    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const { line: personnel } = await lineOf(de, state.budgetOneId, "Personnel");

    // 250,000 left on Personnel 2026; this is 300,000
    const big = await newExpense(de, { budgetLine: personnel._id, description: "Consultant fees", amount: 300000 });
    assert.equal(big.status, 201);
    assert.equal(big.data.data.line.overBudget, true, "the form can warn before submitting");
    const id = big.data.data._id;

    assert.equal((await api("POST", `/expenses/${id}/submit`, { token: de })).status, 200, "submitting is allowed");

    const plain = await api("POST", `/expenses/${id}/approve`, { token: fin, body: {} });
    assert.equal(plain.status, 400);
    assert.equal(plain.data.errors?.[0]?.code, "OVER_BUDGET");

    const noReason = await api("POST", `/expenses/${id}/approve`, { token: fin, body: { allowOverBudget: true } });
    assert.equal(noReason.status, 400);

    const ok = await api("POST", `/expenses/${id}/approve`, { token: fin, body: { allowOverBudget: true, comment: "Board approved reallocation" } });
    assert.equal(ok.status, 200, ok.data?.message);
    assert.equal(ok.data.data.approvedOverBudget, true);

    const { line } = await lineOf(de, state.budgetOneId, "Personnel");
    assert.equal(line.amounts.find(item => item.fiscalYear === 2026).remaining, -50000);

    // Voiding gives the money back
    assert.equal((await api("POST", `/expenses/${id}/void`, { token: fin, body: {} })).status, 400, "a reason is required");
    const voided = await api("POST", `/expenses/${id}/void`, { token: fin, body: { comment: "Paid from another grant" } });
    assert.equal(voided.status, 200);
    assert.equal(voided.data.data.status, "Voided");

    const after = await lineOf(de, state.budgetOneId, "Personnel");
    assert.equal(after.line.amounts.find(item => item.fiscalYear === 2026).remaining, 250000);

});


test("expenses: foreign currency needs a rate; return needs a comment", { skip }, async () => {

    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const { line: training } = await lineOf(de, state.budgetOneId, "Training & Workshops");

    const noRate = await newExpense(de, { budgetLine: training._id, description: "Venue (USD invoice)", amount: 100, currency: "USD" });
    assert.equal(noRate.status, 400);
    assert.match(noRate.data.message, /exchange rate/);

    const usd = await newExpense(de, { budgetLine: training._id, description: "Venue (USD invoice)", amount: 100, currency: "USD", exchangeRate: 57.5 });
    assert.equal(usd.status, 201, usd.data?.message);
    assert.equal(usd.data.data.budgetAmount, 5750);
    assert.equal(usd.data.data.budgetCurrency, "ETB");

    await api("POST", `/expenses/${usd.data.data._id}/submit`, { token: de });
    assert.equal((await api("POST", `/expenses/${usd.data.data._id}/return`, { token: fin, body: {} })).status, 400);
    const returned = await api("POST", `/expenses/${usd.data.data._id}/return`, { token: fin, body: { comment: "Attach the invoice number" } });
    assert.equal(returned.data.data.status, "Returned");

    // Returned can be edited and deleted again
    assert.equal((await api("PUT", `/expenses/${usd.data.data._id}`, { token: de, body: { referenceNumber: "INV-778" } })).status, 200);
    assert.equal((await api("DELETE", `/expenses/${usd.data.data._id}`, { token: de })).status, 200);

    // Other organizations cannot see expenses
    assert.equal((await api("GET", `/expenses/${state.expenseOne}`, { token: state.tokenB })).status, 404);

});


test("expenses: two approvals at once cannot both use the last of a line", { skip }, async () => {

    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const { line: training } = await lineOf(de, state.budgetOneId, "Training & Workshops");

    // 200,000 on Training 2026: each fits alone, not both
    const ids = [];
    for (const name of ["Workshop A", "Workshop B"]) {
        const res = await newExpense(de, { budgetLine: training._id, description: name, amount: 150000 });
        assert.equal(res.status, 201);
        await api("POST", `/expenses/${res.data.data._id}/submit`, { token: de });
        ids.push(res.data.data._id);
    }

    const results =
        await Promise.all(ids.map(id => api("POST", `/expenses/${id}/approve`, { token: fin, body: {} })));

    const statuses = results.map(res => res.status).sort();
    assert.deepEqual(statuses, [200, 400], `got ${statuses.join(", ")}: ${results.map(r => r.data?.message).join(" | ")}`);

    const { line } = await lineOf(de, state.budgetOneId, "Training & Workshops");
    assert.equal(line.amounts.find(item => item.fiscalYear === 2026).spent, 150000);

    // Program budget shows its projects' spending
    const program = (await api("GET", `/budgets/${state.envelopeId}`, { token: de })).data.data;
    assert.equal(program.summary.years.find(item => item.fiscalYear === 2026).spent, 300000);

});


// =====================================================
// FINANCE REPORTS
// =====================================================
//
// By now on budget one (FY 2026): Personnel 150,000 approved
// (the 300,000 one was voided), Training 150,000 approved.
//
// =====================================================

test("reports: budget and spending, by category and donor", { skip }, async () => {

    const fin = state.financeToken;

    const res = await api("GET", "/report-center/budgets?period=year&year=2026", { token: fin });
    assert.equal(res.status, 200, res.data?.message);

    const report = res.data.data;
    const figure = (label) => report.summary.find(item => item.label === label)?.value;

    assert.equal(figure("Budget for FY 2026"), "ETB 600,000.00");
    assert.equal(figure("Spent"), "ETB 300,000.00");

    const personnel = report.sections.find(item => item.key === "category").rows.find(row => row.label === "Personnel");
    assert.equal(personnel.spent, 150000);
    assert.equal(personnel.remaining, 250000);

    const unlinked = report.sections.find(item => item.key === "donor").rows.find(row => row.label === "Not linked to a donation");
    assert.equal(unlinked.expenses, 2);

    // Other organizations see none of it
    const other = await api("GET", "/report-center/budgets?period=year&year=2026", { token: state.tokenB });
    assert.equal(other.status, 200);
    assert.equal(other.data.data.summary.find(item => item.label === "Project budgets").value, 0);

});


test("budget numbers come only from the Budgets module", { skip }, async () => {

    const token = state.tokenA;

    // A typed budget on the program / project form is ignored
    const typed = await api("POST", "/programs", {
        token,
        body: { name: "Typed Budget Program", startDate: "2026-01-01", budget: 999999 }
    });
    assert.ok(typed.status < 300, typed.data?.message);
    const typedProgram = (await api("GET", `/programs/${typed.data.data._id}`, { token })).data.data;
    assert.equal(typedProgram.budget, null, "no budget in Budgets = no budget");

    const typedProject = await api("POST", "/projects", {
        token,
        body: { program: typed.data.data._id, name: "Typed Budget Project", startDate: "2026-01-01", endDate: "2026-12-31", approvedBudget: 5000 }
    });
    assert.ok(typedProject.status < 300, typedProject.data?.message);
    const typedProjectDetails = (await api("GET", `/projects/${typedProject.data.data._id}`, { token })).data.data;
    assert.equal(typedProjectDetails.budget, null);
    assert.equal(typedProjectDetails.approvedBudget, undefined);

    // Program: its approved budget, spent = its projects' approved expenses
    const program = (await api("GET", `/programs/${state.budgetProgramId}`, { token })).data.data;
    assert.equal(program.budget.status, "Approved");
    assert.equal(program.budget.approvedAmount, 3000000);
    assert.equal(program.budget.spent, 300000);
    assert.equal(program.budget.remaining, 2700000);

    // Project: same figures on the list and the details page
    const project = (await api("GET", `/projects/${state.projectOne}`, { token })).data.data;
    assert.equal(project.budget.budgetId, state.budgetOneId);
    assert.equal(project.budget.approvedAmount, 1100000);
    assert.equal(project.budget.spent, 300000);

    const list = (await api("GET", `/projects?program=${state.budgetProgramId}`, { token })).data.data;
    assert.equal(list.find(item => item._id === state.projectOne).budget.approvedAmount, 1100000);

    const programs = (await api("GET", "/programs?search=Budget%20Test%20Program", { token })).data.data;
    assert.equal(programs[0].budget.approvedAmount, 3000000);

    // Programs & projects report reads the Budgets module too
    const report = await api("GET", "/report-center/programs?period=year&year=2026", { token });
    assert.equal(report.status, 200, report.data?.message);
    const row = report.data.data.details.rows.find(item => item.name === "Budget Project One");
    assert.equal(row.approved, 1100000);
    assert.equal(row.spentToDate, 300000);
    assert.equal(row.budgetCurrency, "ETB");
    assert.equal(report.data.data.details.rows.find(item => item.name === "Typed Budget Project").approved, null);
    assert.equal(report.data.data.sections[0].rows.find(item => item.name === "Budget Test Program").approved, 3000000);

    // Dashboard: approved program budgets per currency
    const dashboard = await api("GET", "/dashboard?period=annual&year=2026", { token });
    assert.equal(dashboard.status, 200, dashboard.data?.message);
    assert.equal(dashboard.data.data.statistics.budget.byCurrency.ETB, 3000000);

});


test("free plan: 5 users (admin + 4), the 6th is refused", { skip }, async () => {

    // Organization B is on the Free plan with only its admin
    for (let i = 1; i <= 4; i++) {
        const res = await api("POST", "/users", {
            token: state.tokenB,
            body: { name: `Free User ${i}`, email: `free${i}@test.local`, password: "FreeUser2026x", role: i === 1 ? "finance_officer" : "data_entry", mustChangePassword: false }
        });
        assert.ok(res.status < 300, `user ${i}: ${res.status} ${res.data?.message}`);
    }

    const sixth = await api("POST", "/users", {
        token: state.tokenB,
        body: { name: "Free User 5", email: "free5@test.local", password: "FreeUser2026x", role: "viewer", mustChangePassword: false }
    });
    assert.ok(sixth.status >= 400 && sixth.status < 500, `6th user: ${sixth.status}`);

});


test("funding: received only, never added across currencies", { skip }, async () => {

    const token = state.tokenB;

    const donor = await api("POST", "/donors", { token, body: { name: "Currency Test Donor", donorType: "Foundation" } });
    assert.ok(donor.status < 300, donor.data?.message);

    const donation = (title, amount, currency, status, extra = {}) =>
        api("POST", "/donations", {
            token,
            body: { donor: donor.data.data._id, title, amount, currency, status, donationDate: "2026-03-01", ...extra }
        });

    assert.ok((await donation("ETB grant", 1000000, "ETB", "Received")).status < 300);

    // received in EUR: the rate on that day is needed
    const noRate = await donation("EUR grant", 5000, "EUR", "Received");
    assert.equal(noRate.status, 400);
    assert.match(noRate.data.message, /exchange rate on the day this EUR donation was received/);
    const eur = await donation("EUR grant", 5000, "EUR", "Received", { receivedRate: 130 });
    assert.ok(eur.status < 300, eur.data?.message);
    assert.equal(new Date(eur.data.data.receivedRateDate).toISOString().slice(0, 10), "2026-03-01", "dated the day it was received");
    assert.ok((await donation("EUR pledge", 100, "EUR", "Pledged")).status < 300, "a pledge may have no rate yet");
    assert.ok((await donation("ETB pledge", 300000, "ETB", "Pledged")).status < 300);

    const dashboard = await api("GET", "/dashboard?period=annual&year=2026", { token });
    assert.equal(dashboard.status, 200, dashboard.data?.message);
    assert.equal(dashboard.data.data.summary.totalFunding, 1000000, "ETB received only");
    assert.deepEqual(dashboard.data.data.summary.fundingByCurrency, { ETB: 1000000, EUR: 5000 });

    const donors = await api("GET", "/report-center/donors?period=year&year=2026", { token });
    assert.equal(donors.status, 200, donors.data?.message);
    const figure = (label) => donors.data.data.summary.find(item => item.label === label)?.value;
    assert.equal(figure("Received"), "ETB 1,000,000.00 + EUR 5,000.00");
    assert.equal(figure("Received, in ETB (each at its received rate)"), "ETB 1,650,000.00");
    assert.equal(figure("Pledged, not yet received"), "ETB 300,000.00 + EUR 100.00");

    // the donor's figures stay in EUR; ETB: received at 130, used at the rate when spent (140)
    const { item, create, people } = await serviceDeliverySetupFor(token);
    const kits = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 10, { currency: "EUR", exchangeRate: 140, donor: donor.data.data._id, donation: eur.data.data._id })], beneficiaries: people });
    assert.ok(kits.status < 300, kits.data?.message);
    const funding = (await api("GET", `/donations/${eur.data.data._id}`, { token })).data.data.funding;
    assert.deepEqual([funding.used, funding.left], [20, 4980]);
    assert.deepEqual(
        [funding.inBase.received, funding.inBase.usedWhenSpent, funding.inBase.usedAtReceivedRate, funding.inBase.exchangeDifference, funding.inBase.left],
        [650000, 2800, 2600, 200, 647400]
    );

});




// =====================================================
// BUDGET REVISIONS
// =====================================================
//
// Budget one (approved, v1): Personnel 2026 = 400,000 with
// 150,000 spent; Training 2026 = 200,000 with 150,000 spent.
// Program budget: 1,000,000 a year.
//
// =====================================================

const revisedLines = (budget, change) =>
    budget.lines.map(line => ({
        _id: line._id,
        category: line.category,
        description: line.description,
        amounts: line.amounts.map(item => ({
            fiscalYear: item.fiscalYear,
            amount: change(line, item.fiscalYear, item.amount)
        }))
    }));


test("revisions: protect spending, ceiling and require a reason", { skip }, async () => {

    const fin = state.financeToken;
    const id = state.budgetOneId;

    const started = await api("POST", `/budgets/${id}/revision`, { token: fin });
    assert.equal(started.status, 201, started.data?.message);
    assert.equal(started.data.data.revision.status, "Draft");
    assert.equal(started.data.data.status, "Approved", "the approved figures stay in force");

    assert.equal((await api("POST", `/budgets/${id}/revision`, { token: fin })).status, 409, "only one revision at a time");

    const budget = started.data.data;
    const set = (lines, extra = {}) => api("PUT", `/budgets/${id}/revision`, { token: fin, body: { lines, ...extra } });
    const submit = () => api("POST", `/budgets/${id}/revision/submit`, { token: fin });

    // Below what is spent
    await set(revisedLines(budget, (line, year, amount) => (line.category === "Personnel" && year === 2026 ? 100000 : amount)), { reason: "Cut personnel" });
    const belowSpent = await submit();
    assert.equal(belowSpent.status, 400);
    assert.match(belowSpent.data.message, /already spent/);

    // Removing a line that has expenses
    const withoutTraining =
        revisedLines(budget, (line, year, amount) => amount).filter(line => line.category !== "Training & Workshops");
    await set(withoutTraining);
    const removed = await submit();
    assert.equal(removed.status, 400);
    assert.match(removed.data.message, /cannot be removed/);

    // Over the program ceiling (1,000,000 in 2026)
    await set(revisedLines(budget, (line, year, amount) => (line.category === "Personnel" && year === 2026 ? 2000000 : amount)));
    assert.equal((await submit()).status, 400);

    // A reason is required: asked for when the revision is saved,
    // not only at submit (the draft keeps its earlier reason)
    const proposal = revisedLines(budget, (line, year, amount) => (line.category === "Personnel" && year === 2026 ? 450000 : amount));
    const noReason = await set(proposal, { reason: "" });
    assert.equal(noReason.status, 400);
    assert.match(noReason.data.message, /reason/i);
    assert.ok((await set(proposal)).status < 300, "saved with the reason it already has");

});


test("revisions: approval makes a new version and keeps expenses linked", { skip }, async () => {

    const fin = state.financeToken;
    const de = state.dataEntryToken;
    const id = state.budgetOneId;

    const before = (await api("GET", `/budgets/${id}`, { token: fin })).data.data;
    const personnelId = before.lines.find(line => line.category === "Personnel")._id;

    // Before the revision: Personnel 2026 = 400,000 with 150,000 spent.
    // A 270,000 expense approved over budget puts the line at 420,000.
    const over = await newExpense(de, { budgetLine: personnelId, description: "Second facilitator, Jan-Mar", amount: 270000 });
    assert.equal(over.status, 201, over.data?.message);
    await api("POST", `/expenses/${over.data.data._id}/submit`, { token: de });
    const overApproved = await api("POST", `/expenses/${over.data.data._id}/approve`, {
        token: fin, body: { allowOverBudget: true, comment: "Revision to follow" }
    });
    assert.equal(overApproved.status, 200, overApproved.data?.message);

    const listed = async () =>
        (await api("GET", `/expenses?budget=${id}&limit=100`, { token: fin })).data.data
            .find(item => item._id === over.data.data._id);
    assert.equal((await listed()).lineOverBudget, true, "over before the revision");

    await api("PUT", `/budgets/${id}/revision`, { token: fin, body: { reason: "Second facilitator from April" } });
    assert.equal((await api("POST", `/budgets/${id}/revision/submit`, { token: fin })).status, 200);

    // Data entry cannot approve
    assert.equal((await api("POST", `/budgets/${id}/revision/approve`, { token: de, body: {} })).status, 403);

    const approved = await api("POST", `/budgets/${id}/revision/approve`, { token: fin, body: { comment: "OK" } });
    assert.equal(approved.status, 200, approved.data?.message);

    const after = approved.data.data;
    assert.equal(after.version, 2);
    assert.equal(after.revision, null);
    assert.equal(after.versions.length, 1);
    assert.equal(after.versions[0].version, 1);
    assert.equal(after.versions[0].replacedBecause, "Second facilitator from April");

    const personnel = after.summary.lines.find(line => line.category === "Personnel");
    assert.equal(String(personnel._id), String(personnelId), "line id kept, so expenses stay attached");
    const year = personnel.amounts.find(item => item.fiscalYear === 2026);
    assert.equal(year.amount, 450000);
    assert.equal(year.spent, 420000);
    assert.equal(year.remaining, 30000);

    // The revision covers it: no longer shown as over (the
    // over-budget approval is still on record)
    const now = await listed();
    assert.equal(now.lineOverBudget, false, "covered by the revision");
    assert.equal(now.approvedOverBudget, true);

    // Old figures are kept in the version
    const oldPersonnel = after.versions[0].lines.find(line => line.category === "Personnel");
    assert.equal(oldPersonnel.amounts.find(item => item.fiscalYear === 2026).amount, 400000);

});


test("revisions: return and cancel", { skip }, async () => {

    const fin = state.financeToken;
    const id = state.budgetOneId;

    assert.equal((await api("POST", `/budgets/${id}/revision`, { token: fin })).status, 201);
    await api("PUT", `/budgets/${id}/revision`, { token: fin, body: { reason: "Try a change" } });
    await api("POST", `/budgets/${id}/revision/submit`, { token: fin });

    // Submitted revisions cannot be edited or cancelled
    assert.equal((await api("PUT", `/budgets/${id}/revision`, { token: fin, body: { reason: "x y z" } })).status, 409);

    assert.equal((await api("POST", `/budgets/${id}/revision/return`, { token: fin, body: {} })).status, 400, "comment required");
    const returned = await api("POST", `/budgets/${id}/revision/return`, { token: fin, body: { comment: "Not needed now" } });
    assert.equal(returned.data.data.revision.status, "Returned");

    const cancelled = await api("DELETE", `/budgets/${id}/revision`, { token: fin });
    assert.equal(cancelled.status, 200);
    assert.equal(cancelled.data.data.revision, null);
    assert.equal(cancelled.data.data.version, 2, "cancelling changes nothing");

});


// =====================================================
// ERROR CODES + SEARCH
// =====================================================

// =====================================================
// SERVICE DELIVERY
// =====================================================

const serviceDeliverySetup = () => serviceDeliverySetupFor(state.tokenA, "sd");

// the same, for any organization (B: other phone numbers)
const serviceDeliverySetupFor = async (token, cacheKey = "sdB") => {

    if (state[cacheKey]) return state[cacheKey];

    const lookups = async (module, category) =>
        (await api("GET", `/lookups/module/${module}/category/${category}`, { token })).data.data;

    const types = await lookups("ServiceDelivery", "ServiceType");
    const units = Object.fromEntries((await lookups("ServiceDelivery", "Unit")).map(unit => [unit.value, unit._id]));
    const genders = Object.fromEntries((await lookups("Beneficiary", "Gender")).map(gender => [gender.value, gender._id]));

    const program = await api("POST", "/programs", { token, body: { name: "Service Delivery Test Program", startDate: "2026-01-01" } });
    assert.ok(program.status < 300, program.data?.message);

    const people = [];
    for (const [index, [firstName, lastName]] of [["Almaz", "Kebede"], ["Hana", "Tesfaye"], ["Selam", "Girma"]].entries()) {
        const person = await api("POST", "/beneficiaries", {
            token,
            body: { firstName, lastName, gender: genders.Female, dateOfBirth: "1995-03-10", phone: `0912${cacheKey === "sd" ? "00" : "11"}000${index}` }
        });
        assert.ok(person.status < 300, person.data?.message);
        people.push(person.data.data._id);
    }

    const item = (typeName, unitName, quantity, unitCost, extra = {}) => {
        const type = types.find(found => found.value === typeName);
        assert.ok(type, `service type ${typeName}`);
        return {
            _id: new mongoose.Types.ObjectId().toString(),
            serviceCategory: String(type.parentLookup?._id || type.parentLookup),
            serviceType: type._id,
            quantity,
            unit: units[unitName],
            unitCost,
            ...extra
        };
    };

    const create = (body) =>
        api("POST", "/service-deliveries", {
            token,
            body: { program: program.data.data._id, deliveryDate: "2026-05-01", status: "Delivered", ...body }
        });

    const shares = (serviceItem, quantity, allocatedValue, extra = {}) =>
        people.map(beneficiary => ({
            beneficiary,
            allocations: [{ serviceItem: serviceItem._id, quantity, ...(allocatedValue === undefined ? {} : { allocatedValue }), ...extra }]
        }));

    state[cacheKey] = { token, units, people, item, create, shares };

    return state[cacheKey];

};


test("service delivery: behavior comes from the service type, not the client", { skip }, async () => {

    const { token, item, create, shares } = await serviceDeliverySetup();

    // A training: everyone takes part in all 3 sessions
    const training = item("Business Skills Training", "Session", 3, 1000);
    const accepted = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [training], beneficiaries: shares(training, 3, 1000) });
    assert.ok(accepted.status < 300, accepted.data?.message);

    const saved = await api("GET", `/service-deliveries/${accepted.data.data._id}`, { token });
    assert.equal(saved.data.data.items[0].allocationBehavior, "PARTICIPATION");

    // Hygiene kits are used up: claiming PARTICIPATION does not let 2 kits reach 6 people
    const kits = item("Hygiene Kit", "Set", 2, 750, { allocationBehavior: "PARTICIPATION" });
    const refused = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [kits], beneficiaries: shares(kits, 2, 500) });
    assert.equal(refused.status, 400);

});


test("service delivery: units, whole numbers and detail items", { skip }, async () => {

    const { units, people, item, create } = await serviceDeliverySetup();

    const shared = (items) => create({ recipientType: "Individual", allocationMethod: "Shared", items, beneficiaries: people });

    // a unit the service type does not allow
    const wrongUnit = await shared([item("School Fees", "Kg", 5, 100)]);
    assert.equal(wrongUnit.status, 400);
    assert.match(wrongUnit.data.message, /cannot be recorded in/);

    // weights take parts, countable things do not
    assert.ok((await shared([item("Food Assistance", "Kg", 12.5, 80)])).status < 300);
    const halfKit = await shared([item("Hygiene Kit", "Set", 2.5, 750)]);
    assert.equal(halfKit.status, 400);
    assert.match(halfKit.data.message, /whole number/);

    // the breakdown must add up to the item's cost
    const mismatch = await shared([item("School Supplies", "Set", 2, 100, { detailItems: [{ name: "Books", quantity: 10, unit: units.Piece, unitCost: 100 }] })]);
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.data.message, /must be equal/);

    // a detail item needs a unit
    const noUnit = await shared([item("School Supplies", "Set", 3, 100, { detailItems: [{ name: "Books", quantity: 3, unitCost: 100 }] })]);
    assert.equal(noUnit.status, 400);
    assert.match(noUnit.data.message, /needs a unit/);

    // cash is not broken down into goods
    const cashToGoods = await shared([item("Cash Assistance", "ETB", 3, 1000, { detailItems: [{ name: "Rice", quantity: 3, unit: units.Kg, unitCost: 1000 }] })]);
    assert.equal(cashToGoods.status, 400);

});


test("service delivery: shares, conversion and automatic values", { skip }, async () => {

    const { token, units, people, item, create, shares } = await serviceDeliverySetup();

    // Individual allocation: everyone needs a share
    const kits = item("Hygiene Kit", "Set", 3, 750);
    const missing = await create({
        recipientType: "Individual",
        allocationMethod: "Individual",
        items: [kits],
        beneficiaries: [
            { beneficiary: people[0], allocations: [{ serviceItem: kits._id, quantity: 1, allocatedValue: 750 }] },
            { beneficiary: people[1], allocations: [{ serviceItem: kits._id, quantity: 1, allocatedValue: 750 }] },
            { beneficiary: people[2], allocations: [] }
        ]
    });
    assert.equal(missing.status, 400);
    assert.match(missing.data.message, /1 of 3/);

    // 1 sack = 50 Kg: 10 Kg to each of 3 people fits
    const detailId = new mongoose.Types.ObjectId().toString();
    const rice = item("Food Assistance", "Kg", 1, 2500, {
        detailItems: [{ _id: detailId, name: "Rice sack", quantity: 1, unit: units.Piece, allocationUnit: units.Kg, allocationConversionFactor: 50, unitCost: 2500 }]
    });
    const sack = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [rice], beneficiaries: shares(rice, 10, 500, { detailItem: detailId }) });
    assert.ok(sack.status < 300, sack.data?.message);

    // ...but 20 Kg each (60 of 50) does not
    const rice2 = { ...rice, _id: new mongoose.Types.ObjectId().toString() };
    const tooMuch = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [rice2], beneficiaries: shares(rice2, 20, 0, { detailItem: detailId }) });
    assert.equal(tooMuch.status, 400);

    // values left empty are worked out: one kit each = 750 each
    const kits2 = item("Hygiene Kit", "Set", 3, 750);
    const automatic = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [kits2], beneficiaries: shares(kits2, 1) });
    assert.ok(automatic.status < 300, automatic.data?.message);

    const saved = await api("GET", `/service-deliveries/${automatic.data.data._id}`, { token });
    assert.deepEqual(saved.data.data.beneficiaries.map(person => person.allocations[0].allocatedValue), [750, 750, 750]);

    // an institution is not split among people
    const institution = await create({ recipientType: "Institution", recipientName: "Test School", allocationMethod: "Group", items: [item("School Supplies", "Set", 10, 100)], beneficiaries: people });
    assert.equal(institution.status, 400);

});


test("service delivery: a donation cannot pay for more than it has left", { skip }, async () => {

    const { token, people, item, create } = await serviceDeliverySetup();

    const donor = await api("POST", "/donors", { token, body: { name: "Balance Test Donor", donorType: "Foundation" } });
    assert.ok(donor.status < 300, donor.data?.message);

    const donation = async (title, amount, status) => {
        const res = await api("POST", "/donations", {
            token,
            body: { donor: donor.data.data._id, title, amount, currency: "ETB", status, donationDate: "2026-03-01" }
        });
        assert.ok(res.status < 300, res.data?.message);
        return res.data.data._id;
    };

    const grant = await donation("Cash grant", 100000, "Received");

    const cash = (amount, donationId) =>
        item("Cash Assistance", "ETB", 1, amount, { donor: donor.data.data._id, donation: donationId });

    // 100,000 ETB: 50,000 each to two people, individually
    const both = cash(100000, grant);
    const paidBody = {
        recipientType: "Individual",
        allocationMethod: "Individual",
        items: [both],
        beneficiaries: people.slice(0, 2).map(beneficiary => ({ beneficiary, allocations: [{ serviceItem: both._id, quantity: 0, allocatedValue: 50000 }] }))
    };
    const paid = await create(paidBody);
    assert.ok(paid.status < 300, paid.data?.message);

    // nothing is left of the grant now
    const more = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(1000, grant)], beneficiaries: people });
    assert.equal(more.status, 400);
    assert.match(more.data.message, /has ETB 0\.00 left/);

    // a cancelled delivery uses no money
    const cancelled = await create({ status: "Cancelled", recipientType: "Individual", allocationMethod: "Shared", items: [cash(1000, grant)], beneficiaries: people });
    assert.ok(cancelled.status < 300, cancelled.data?.message);

    // a pledge can be charged up to its amount
    const pledge = await donation("Book pledge", 50000, "Pledged");
    assert.equal((await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(200000, pledge)], beneficiaries: people })).status, 400);
    assert.ok((await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(50000, pledge)], beneficiaries: people })).status < 300);

    // editing a delivery does not count its own old cost against it
    const resave = await api("PUT", `/service-deliveries/${paid.data.data._id}`, {
        token,
        body: { program: paid.data.data.program?._id || paid.data.data.program, deliveryDate: "2026-05-01", status: "Delivered", remarks: "checked", ...paidBody }
    });
    assert.ok(resave.status < 300, resave.data?.message);

});


test("service delivery: with individual allocation, cash is shared out in full", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();

    const cash = item("Cash Assistance", "ETB", 1, 20000);
    const shares = (first, second) => [
        { beneficiary: people[0], allocations: [{ serviceItem: cash._id, quantity: 0, allocatedValue: first }] },
        { beneficiary: people[1], allocations: [{ serviceItem: cash._id, quantity: 0, allocatedValue: second }] }
    ];

    // 15,000 + 2,000 of 20,000 leaves 3,000 with no one
    const short = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [cash], beneficiaries: shares(15000, 2000) });
    assert.equal(short.status, 400);
    assert.match(short.data.message, /3,000\.00 is left with no one/);

    const full = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [{ ...cash, _id: new mongoose.Types.ObjectId().toString() }], beneficiaries: [] });
    assert.equal(full.status, 400, "no beneficiaries is still refused");

    const cash2 = { ...cash, _id: new mongoose.Types.ObjectId().toString() };
    const ok = await create({
        recipientType: "Individual",
        allocationMethod: "Individual",
        items: [cash2],
        beneficiaries: [
            { beneficiary: people[0], allocations: [{ serviceItem: cash2._id, quantity: 0, allocatedValue: 18000 }] },
            { beneficiary: people[1], allocations: [{ serviceItem: cash2._id, quantity: 0, allocatedValue: 2000 }] }
        ]
    });
    assert.ok(ok.status < 300, ok.data?.message);

});


test("reports: people and enterprises count each person's own share", { skip }, async () => {

    const { token, people, item, create, shares } = await serviceDeliverySetup();

    const valueReceived = async () => {
        const res = await api("GET", "/report-center/beneficiaries?period=year&year=2026", { token });
        assert.equal(res.status, 200, res.data?.message);
        return res.data.data.summary.find(item => item.label === "Value received").value;
    };

    const before = await valueReceived();

    // 3 kits worth 2,250 to 3 people: 750 each, not 2,250 each
    const kits = item("Hygiene Kit", "Set", 3, 750);
    const delivery = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [kits], beneficiaries: shares(kits, 1, 750) });
    assert.ok(delivery.status < 300, delivery.data?.message);

    const after = await valueReceived();
    assert.equal(Math.round((after - before) * 100) / 100, 2250);

    // two of them run an enterprise: it received 1,500 and 2 kits
    const enterprise = await api("POST", "/enterprises", { token, body: { name: "Test Enterprise", beneficiaries: [people[0], people[1]] } });
    assert.ok(enterprise.status < 300, enterprise.data?.message);

    const profile = await api("GET", `/report-center/detail/enterprise/${enterprise.data.data._id}`, { token });
    assert.equal(profile.status, 200, profile.data?.message);

    const support = profile.data.data.sections.find(item => item.key === "support").rows;
    const fromThisDelivery = support.filter(row => String(row.id) === String(delivery.data.data._id));
    assert.equal(fromThisDelivery.length, 2, "one row per member");
    assert.equal(fromThisDelivery.reduce((sum, row) => sum + Number(row.value), 0), 1500);

});


test("report center: eight reports, the same figures everywhere, detail reports and files", { skip }, async () => {

    const token = state.tokenA;

    const catalog = await api("GET", "/report-center", { token });
    assert.equal(catalog.status, 200);
    assert.deepEqual(catalog.data.data.map(report => report.key),
        ["overview", "beneficiaries", "programs", "activities", "serviceDelivery", "enterprises", "donors", "budgets"]);

    const run = async (key, extra = "") => {
        const res = await api("GET", `/report-center/${key}?period=year&year=2026${extra}`, { token });
        assert.equal(res.status, 200, `${key}: ${res.data?.message}`);
        assert.ok(Array.isArray(res.data.data.summary) && Array.isArray(res.data.data.sections), key);
        return res.data.data;
    };

    const reports = {};
    for (const report of catalog.data.data) reports[report.key] = await run(report.key);

    const figure = (key, label) => reports[key].summary.find(item => item.label === label)?.value;

    // one figure, one count: the reports agree
    assert.equal(figure("beneficiaries", "Value received"), figure("serviceDelivery", "Given to people"));
    assert.equal(figure("overview", "Beneficiaries reached"), figure("beneficiaries", "Reached by services"));
    assert.equal(figure("overview", "Value delivered"), figure("serviceDelivery", "Value delivered"));
    assert.equal(figure("programs", "Value delivered"), figure("serviceDelivery", "Value delivered"));
    assert.ok(figure("serviceDelivery", "Deliveries") > 0, "the earlier tests delivered services");

    // the deliveries' value adds up
    const delivery = reports.serviceDelivery;
    const parts = figure("serviceDelivery", "Given to people") + figure("serviceDelivery", "To institutions") + figure("serviceDelivery", "To households and groups") + figure("serviceDelivery", "Not given out");
    assert.ok(Math.abs(parts - figure("serviceDelivery", "Value delivered")) < 0.05, `${parts} vs ${figure("serviceDelivery", "Value delivered")}`);
    assert.equal(delivery.details.rows.length, figure("serviceDelivery", "Deliveries"));

    // trainings: completion never exceeds the people trained
    assert.ok(figure("activities", "Completed every session") <= figure("activities", "People trained"));
    assert.ok(reports.activities.sections.some(item => item.key === "trainings"));
    assert.ok(reports.activities.sections.some(item => item.key === "others"));

    // institutions and households / groups are counted the same in every report
    assert.equal(figure("programs", "Institutions reached"), figure("serviceDelivery", "Institutions reached"));
    assert.equal(figure("overview", "Institutions reached"), figure("serviceDelivery", "Institutions reached"));
    assert.equal(figure("programs", "Households and groups reached"), figure("serviceDelivery", "Households and groups reached"));

    // a period with nothing in it
    const emptyRes = await api("GET", "/report-center/serviceDelivery?period=year&year=2001", { token });
    assert.equal(emptyRes.status, 200);
    const empty = emptyRes.data.data;
    assert.equal(empty.summary.find(item => item.label === "Deliveries").value, 0);

    // detail reports open from the rows
    const person = reports.beneficiaries.details.rows.find(row => row.services > 0);
    const profile = await api("GET", `/report-center/detail/beneficiary/${person.id}`, { token });
    assert.equal(profile.status, 200, profile.data?.message);
    assert.equal(profile.data.data.summary.find(item => item.label === "Value received").value, person.value);

    for (const [kind, row] of [["program", reports.programs.sections[0].rows[0]], ["project", reports.programs.details.rows[0]]]) {
        const res = await api("GET", `/report-center/detail/${kind}/${row.id}`, { token });
        assert.equal(res.status, 200, `${kind}: ${res.data?.message}`);
    }

    assert.equal((await api("GET", "/report-center/detail/beneficiary/64b000000000000000000000", { token })).status, 404);
    assert.equal((await api("GET", "/report-center/nothing", { token })).status, 404);

    // another organization sees none of it
    const other = await api("GET", `/report-center/detail/beneficiary/${person.id}`, { token: state.tokenB });
    assert.equal(other.status, 404);

    // files
    for (const [format, type] of [["excel", "spreadsheetml"], ["pdf", "application/pdf"], ["csv", "text/csv"]]) {
        const response = await fetch(`${BASE}/report-center/beneficiaries?period=year&year=2026&format=${format}`, { headers: { Authorization: `Bearer ${token}` } });
        assert.equal(response.status, 200, format);
        assert.ok(String(response.headers.get("content-type")).includes(type), `${format}: ${response.headers.get("content-type")}`);
        assert.ok((await response.arrayBuffer()).byteLength > 100, format);
    }

});


// =====================================================
// CLIENT FEEDBACK (2026-10-23): allocation, currency,
// recipients, funding, budgets, moving projects
// =====================================================

test("service delivery: goods are worth quantity x price; one level per item; details add up", { skip }, async () => {

    const { token, units, people, item, create } = await serviceDeliverySetup();

    // 1 kit each, values typed as 100: saved as 750 (1 x 750)
    const kits = item("Hygiene Kit", "Set", 2, 750);
    const typed = await create({
        recipientType: "Individual",
        allocationMethod: "Individual",
        items: [kits],
        beneficiaries: people.slice(0, 2).map(beneficiary => ({ beneficiary, allocations: [{ serviceItem: kits._id, quantity: 1, allocatedValue: 100 }] }))
    });
    assert.ok(typed.status < 300, typed.data?.message);
    const saved = (await api("GET", `/service-deliveries/${typed.data.data._id}`, { token })).data.data;
    assert.deepEqual(saved.beneficiaries.map(person => person.allocations[0].allocatedValue), [750, 750]);
    assert.equal(saved.allocationSummary.unallocatedValue, 0);

    // detail items in the item's own unit must add up to its quantity
    const short = await create({
        recipientType: "Individual",
        allocationMethod: "Shared",
        items: [item("School Supplies", "Set", 3, 100, { detailItems: [{ name: "Kit A", quantity: 2, unit: units.Set, unitCost: 150 }] })],
        beneficiaries: people
    });
    assert.equal(short.status, 400);
    assert.match(short.data.message, /add up to 2 .* but the item is 3/);

    // the item or its detail items, the same for everyone
    const detailId = new mongoose.Types.ObjectId().toString();
    const supplies = item("School Supplies", "Set", 2, 100, { detailItems: [{ _id: detailId, name: "Kit A", quantity: 2, unit: units.Set, unitCost: 100 }] });
    const mixed = await create({
        recipientType: "Individual",
        allocationMethod: "Individual",
        items: [supplies],
        beneficiaries: [
            { beneficiary: people[0], allocations: [{ serviceItem: supplies._id, quantity: 1 }] },
            { beneficiary: people[1], allocations: [{ serviceItem: supplies._id, detailItem: detailId, quantity: 1 }] }
        ]
    });
    assert.equal(mixed.status, 400);
    assert.match(mixed.data.message, /either as the whole item or by its detail items/);

});


test("service delivery: a shared training counts sessions once and people once", { skip }, async () => {

    const { token, people, item, create, shares } = await serviceDeliverySetup();

    // 1 training of 3 sessions, 3,000 in all, attended by 3 people
    const training = item("Business Skills Training", "Session", 3, 1000);
    const res = await create({ recipientType: "Individual", allocationMethod: "Individual", items: [training], beneficiaries: shares(training, 3) });
    assert.ok(res.status < 300, res.data?.message);

    const saved = (await api("GET", `/service-deliveries/${res.data.data._id}`, { token })).data.data;
    assert.deepEqual(saved.beneficiaries.map(person => person.allocations[0].allocatedValue), [1000, 1000, 1000], "each takes an equal share of the cost");
    assert.equal(saved.allocationSummary.allocatedValue, 3000);
    assert.equal(saved.allocationSummary.items[0].allocatedText, "3 participants");
    assert.match(saved.allocationSummary.participation[0].text, /^3 Sessions?, 3 participants$/, "not 9 sessions");

});


test("service delivery: items in another currency are kept as entered and counted in ETB", { skip }, async () => {

    const { token, people, item, create } = await serviceDeliverySetup();

    const noRate = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 10, { currency: "EUR" })], beneficiaries: people });
    assert.equal(noRate.status, 400);
    assert.match(noRate.data.message, /exchange rate of the EUR item/);

    const eur = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 10, { currency: "EUR", exchangeRate: 130 })], beneficiaries: people });
    assert.ok(eur.status < 300, eur.data?.message);
    const saved = (await api("GET", `/service-deliveries/${eur.data.data._id}`, { token })).data.data;
    assert.equal(saved.items[0].currency, "EUR");
    assert.equal(saved.items[0].originalUnitCost, 10);
    assert.equal(saved.items[0].unitCost, 1300);
    assert.equal(saved.totalAmount, 2600);

    // cash in ETB cannot be recorded as a EUR item
    const cash = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Cash Assistance", "ETB", 1, 100, { currency: "EUR", exchangeRate: 130 })], beneficiaries: people });
    assert.equal(cash.status, 400);
    assert.match(cash.data.message, /given in ETB/);

});


test("service delivery: who may receive what, and how it is shared", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();

    // school fees are for individuals only
    const fees = await create({ recipientType: "Group / Community", recipientName: "Youth group", allocationMethod: "Group", items: [item("School Fees", "ETB", 1, 5000)], beneficiaries: people });
    assert.equal(fees.status, 400);
    assert.match(fees.data.message, /can only be given to: Individual/);

    // an institution receives the whole item, with no people listed
    const withPeople = await create({ recipientType: "Institution", recipientName: "Test School", allocationMethod: "Unallocated", items: [item("School Supplies", "Set", 10, 100)], beneficiaries: people });
    assert.equal(withPeople.status, 400);
    const school = await create({ recipientType: "Institution", recipientName: "Test School", allocationMethod: "Unallocated", items: [item("School Supplies", "Set", 10, 100)], beneficiaries: [] });
    assert.ok(school.status < 300, school.data?.message);

    // cash may go to a group or an institution as a whole
    const seed = await create({ recipientType: "Group / Community", recipientName: "Savings group", allocationMethod: "Group", items: [item("Cash Assistance", "ETB", 1, 20000)], beneficiaries: people });
    assert.ok(seed.status < 300, seed.data?.message);
    const grant = await create({ recipientType: "Institution", recipientName: "Health post", allocationMethod: "Unallocated", items: [item("Cash Assistance", "ETB", 1, 50000)], beneficiaries: [] });
    assert.ok(grant.status < 300, grant.data?.message);

    // who a service type may go to is set on the service type
    const token = state.tokenA;
    const types = (await api("GET", "/lookups/module/ServiceDelivery/category/ServiceType", { token })).data.data;
    const feesType = types.find(type => type.value === "School Fees");
    assert.deepEqual(feesType.recipientTypes, ["Individual"]);
    const changed = await api("PUT", `/lookups/${feesType._id}`, { token, body: { recipientTypes: ["Individual", "Household"] } });
    assert.ok(changed.status < 300, changed.data?.message);
    assert.deepEqual(changed.data.data.recipientTypes, ["Individual", "Household"]);
    assert.equal((await api("PUT", `/lookups/${feesType._id}`, { token, body: { recipientTypes: ["Robot"] } })).status, 400);
    await api("PUT", `/lookups/${feesType._id}`, { token, body: { recipientTypes: ["Individual"] } });

});


test("funding: restricted donations pay only for their own work; expenses use the balance too", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();
    const token = state.tokenA;

    const donor = (await api("POST", "/donors", { token, body: { name: "Funding Rules Donor", donorType: "Foundation" } })).data.data._id;
    const donation = async (title, amount, extra = {}) => {
        const res = await api("POST", "/donations", { token, body: { donor, title, amount, currency: "ETB", status: "Received", donationDate: "2026-03-01", ...extra } });
        assert.ok(res.status < 300, res.data?.message);
        return res.data.data._id;
    };

    // budget one belongs to project one; project two is another project
    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    const projectOne = String(budget.project?._id || budget.project);
    const program = String(budget.program?._id || budget.program);
    const projectTwo = (await api("POST", "/projects", { token, body: { program, name: "Funding Other Project", startDate: "2026-01-01", endDate: "2026-12-31" } })).data.data._id;

    const restricted = await donation("Only for project one", 50000, { fundingRestriction: "Restricted", program, project: projectOne });
    const kit = (donationId) => item("Hygiene Kit", "Set", 2, 750, { donor, donation: donationId });
    const deliver = (project, donationId) => create({ program, project, recipientType: "Individual", allocationMethod: "Shared", items: [kit(donationId)], beneficiaries: people });

    const elsewhere = await deliver(projectTwo, restricted);
    assert.equal(elsewhere.status, 400);
    assert.match(elsewhere.data.message, /restricted to its project/);
    assert.ok((await deliver(projectOne, restricted)).status < 300);

    const pooled = await donation("Pooled", 50000, { fundingRestriction: "Unrestricted" });
    assert.ok((await deliver(projectTwo, pooled)).status < 300, "unrestricted pays for any work");

    // an expense on another project's restricted donation is refused
    const line = budget.summary.lines[0];
    const otherRestricted = await donation("Only for project two", 5000, { fundingRestriction: "Restricted", program, project: projectTwo });
    const wrong = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Wrong donation", amount: 100, currency: "ETB", donation: otherRestricted });
    assert.equal(wrong.status, 400);
    assert.match(wrong.data.message, /restricted to its project/);

    // 8,000 submitted on a 10,000 donation leaves 2,000 for deliveries
    const small = await donation("Small", 10000);
    const expense = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Uses the donation", amount: 8000, currency: "ETB", donation: small });
    assert.ok(expense.status < 300, expense.data?.message);
    assert.equal((await api("POST", `/expenses/${expense.data.data._id}/submit`, { token: state.dataEntryToken })).status, 200);

    const tooMuch = await create({ program, project: projectOne, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 4, 750, { donor, donation: small })], beneficiaries: people });
    assert.equal(tooMuch.status, 400);
    assert.match(tooMuch.data.message, /ETB 2,000\.00 left .* ETB 8,000\.00 in expenses/);

    const balance = (await api("GET", `/donations/${small}`, { token })).data.data.funding;
    assert.deepEqual([balance.byExpenses, balance.left], [8000, 2000]);

});


test("funding: items bought with an expense are not charged to the donation twice", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();
    const token = state.tokenA;

    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    const project = String(budget.project?._id || budget.project);
    const program = String(budget.program?._id || budget.program);
    const line = budget.summary.lines[0];

    const donor = (await api("POST", "/donors", { token, body: { name: "Kits Donor", donorType: "Foundation" } })).data.data._id;
    const donationId = (await api("POST", "/donations", { token, body: { donor, title: "Kits grant", amount: 100000, currency: "ETB", status: "Received", donationDate: "2026-03-01" } })).data.data._id;
    const funding = async () => (await api("GET", `/donations/${donationId}`, { token })).data.data.funding;

    // 100 kits bought for 75,000 (the expense)
    const bought = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Hygiene kits purchase", amount: 75000, currency: "ETB", donation: donationId });
    assert.ok(bought.status < 300, bought.data?.message);
    const expenseId = bought.data.data._id;
    const expenseCode = bought.data.data.expenseCode;
    assert.equal((await api("POST", `/expenses/${expenseId}/submit`, { token: state.dataEntryToken })).status, 200);

    // ... and given out (75,000): suggested as bought with that expense
    const options = (await api("GET", `/service-deliveries/expense-options?donation=${donationId}&project=${project}&amount=75000`, { token })).data.data;
    assert.equal(options[0].expenseCode, expenseCode);
    assert.equal(options[0].close, true);

    const kits = (quantity, extra = {}) => item("Hygiene Kit", "Set", quantity, 750, { donor, donation: donationId, ...extra });
    const deliver = (items) => create({ program, project, recipientType: "Individual", allocationMethod: "Shared", items, beneficiaries: people });

    // not linked: counted twice, so refused, naming the expense
    const unlinked = await deliver([kits(100)]);
    assert.equal(unlinked.status, 400);
    assert.match(unlinked.data.message, new RegExp(`link them to it .*${expenseCode}`));

    // linked: charged once
    const linked = await deliver([kits(100, { paidByExpense: expenseId })]);
    assert.ok(linked.status < 300, linked.data?.message);
    let now = await funding();
    assert.deepEqual([now.byExpenses, now.byDeliveries, now.givenFromExpenses, now.left], [75000, 0, 75000, 25000]);

    // more kits than the expense bought
    const extra = await deliver([kits(1, { paidByExpense: expenseId })]);
    assert.equal(extra.status, 400);
    assert.match(extra.data.message, /more than the expense/);

    // a second purchase (7,500) and a delivery of it, not linked: the review finds the pair
    const second = (await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "More kits", amount: 7500, currency: "ETB", donation: donationId })).data.data;
    await api("POST", `/expenses/${second._id}/submit`, { token: state.dataEntryToken });
    const small = await deliver([kits(10)]);
    assert.ok(small.status < 300, small.data?.message);
    assert.equal((await funding()).left, 10000, "100,000 - 75,000 - 7,500 - 7,500 (counted twice)");

    const review = (await api("GET", "/service-deliveries/double-counting", { token })).data.data;
    const pair = review.find(found => String(found.delivery._id) === String(small.data.data._id));
    assert.ok(pair, "possible double counting listed");
    assert.equal(pair.expense.expenseCode, second.expenseCode);

    // linked from the review: counted once
    const set = await api("POST", `/service-deliveries/${pair.delivery._id}/items/${pair.item._id}/expense-link`, { token, body: { expense: pair.expense._id } });
    assert.ok(set.status < 300, set.data?.message);
    assert.equal((await funding()).left, 17500);
    assert.ok(!(await api("GET", "/service-deliveries/double-counting", { token })).data.data.some(found => String(found.delivery._id) === String(small.data.data._id)));

    // "separate": not suggested again
    const third = (await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Transport", amount: 1500, currency: "ETB", donation: donationId })).data.data;
    await api("POST", `/expenses/${third._id}/submit`, { token: state.dataEntryToken });
    const two = await deliver([kits(2)]);
    const listed = () => api("GET", "/service-deliveries/double-counting", { token }).then(res => res.data.data.some(found => String(found.delivery._id) === String(two.data.data._id)));
    assert.equal(await listed(), true);
    const itemId = (await api("GET", `/service-deliveries/${two.data.data._id}`, { token })).data.data.items[0]._id;
    assert.ok((await api("POST", `/service-deliveries/${two.data.data._id}/items/${itemId}/expense-link`, { token, body: { expense: third._id, separate: true } })).status < 300);
    assert.equal(await listed(), false);

    // the expense returned (no longer counted): the kits use the donation themselves
    assert.equal((await api("POST", `/expenses/${expenseId}/return`, { token: state.financeToken, body: { comment: "Wrong receipt" } })).status, 200);
    now = await funding();
    assert.equal(now.byDeliveries, 75000 + 1500, "the 100 kits and the 2 separate kits");
    assert.equal(now.givenFromExpenses, 7500);
    assert.equal(now.left, 100000 - 75000 - 1500 - 7500 - 1500);

});


test("budgets: a revision needs its reason when saved; approvers are told; the audit trail has it", { skip }, async () => {

    const token = state.tokenA;
    const finance = state.financeToken;

    // budget one is approved: open a revision
    assert.ok((await api("POST", `/budgets/${state.budgetOneId}/revision`, { token, body: {} })).status < 300);
    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    const lines = budget.revision.lines.map(line => ({ _id: line._id, category: line.category, description: line.description, amounts: line.amounts }));

    const noReason = await api("PUT", `/budgets/${state.budgetOneId}/revision`, { token, body: { lines } });
    assert.equal(noReason.status, 400);
    assert.match(noReason.data.message, /reason/i);
    assert.ok((await api("PUT", `/budgets/${state.budgetOneId}/revision`, { token, body: { lines, reason: "Move staff costs" } })).status < 300);
    assert.equal((await api("POST", `/budgets/${state.budgetOneId}/revision/submit`, { token, body: {} })).status, 200);

    // still approved itself; the revision is waiting and shown as such
    const waiting = await api("GET", "/budgets?waiting=true", { token });
    const row = waiting.data.data.find(found => String(found._id) === String(state.budgetOneId));
    assert.ok(row, "listed as waiting for approval");
    assert.equal(row.status, "Approved");
    assert.equal(row.revision.status, "Submitted");
    const detail = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    assert.ok(detail.approvers.some(person => person.name === "Finance Officer"), "who can approve is shown");

    // the finance officer is told
    const notes = (await api("GET", "/notifications", { token: finance })).data.data;
    const list = Array.isArray(notes) ? notes : notes.items || notes.notifications || [];
    assert.ok(list.some(note => /revision/i.test(`${note.title} ${note.message}`)), "approver notified");

    // returned: written in the audit trail
    assert.equal((await api("POST", `/budgets/${state.budgetOneId}/revision/return`, { token: finance, body: { comment: "Too high" } })).status, 200);
    const logs = (await api("GET", "/organization/audit-logs?limit=50", { token })).data.data;
    const actions = (Array.isArray(logs) ? logs : logs.items || logs.logs || []).map(log => log.action);
    assert.ok(actions.includes("BUDGET_REVISION_SUBMITTED"));
    assert.ok(actions.includes("BUDGET_REVISION_RETURNED"));

    await api("DELETE", `/budgets/${state.budgetOneId}/revision`, { token });

});


test("budgets: a USD project budget under an ETB program budget is converted at its rate", { skip }, async () => {

    const token = state.tokenA;

    const program = (await api("POST", "/programs", { token, body: { name: "Currency Test Program", startDate: "2026-01-01" } })).data.data._id;
    const project = (await api("POST", "/projects", { token, body: { program, name: "USD Project", startDate: "2026-01-01", endDate: "2026-12-31" } })).data.data._id;

    const envelope = (await api("POST", "/budgets", { token, body: { level: "program", name: "ETB envelope", program, startYear: 2026, endYear: 2026, currency: "ETB", yearlyAmounts: yearly({ 2026: 1000000 }) } })).data.data;
    assert.equal((await api("POST", `/budgets/${envelope._id}/submit`, { token })).status, 200);
    assert.equal((await api("POST", `/budgets/${envelope._id}/approve`, { token: state.financeToken, body: {} })).status, 200);

    const usd = (await api("POST", "/budgets", { token, body: { level: "project", name: "USD budget", project, startYear: 2026, endYear: 2026, currency: "USD", lines: [{ category: "Personnel", amounts: yearly({ 2026: 10000 }) }] } })).data.data;

    const noRate = await api("POST", `/budgets/${usd._id}/submit`, { token });
    assert.equal(noRate.status, 400);
    assert.match(noRate.data.message, /exchange rate/i);

    // 10,000 USD x 120 = 1,200,000 ETB: more than the envelope
    await api("PUT", `/budgets/${usd._id}`, { token, body: { programExchangeRate: { rate: 120, date: "2026-10-24" } } });
    assert.equal((await api("POST", `/budgets/${usd._id}/submit`, { token })).status, 400);

    // 8,000 USD = 960,000 ETB fits
    await api("PUT", `/budgets/${usd._id}`, { token, body: { lines: [{ category: "Personnel", amounts: yearly({ 2026: 8000 }) }] } });
    assert.equal((await api("POST", `/budgets/${usd._id}/submit`, { token })).status, 200);

    const year = (await api("GET", `/budgets/${envelope._id}`, { token })).data.data.summary.allocation.years.find(found => found.fiscalYear === 2026);
    assert.equal(year.allocated, 960000);

    // a second budget for the same project is refused, pointing to the first
    const again = await api("POST", "/budgets", { token, body: { level: "project", name: "Again", project, startYear: 2026, endYear: 2026, currency: "USD" } });
    assert.equal(again.status, 409);

});


test("projects in phases: each phase works like a project; the main project groups them", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();
    const token = state.tokenA;

    // these tests add programs and projects beyond the Free
    // plan's 10: give organization A room, as an upgrade would
    const orgA = await state.db.collection("organizations").findOne({ email: "org-a@test.local" });
    await state.db.collection("subscriptions").updateMany(
        { organization: orgA._id },
        { $set: { "planSnapshot.limits.programs": 100, "planSnapshot.limits.projects": 100 } }
    );

    const program = (await api("POST", "/programs", { token, body: { name: "Phased Program", startDate: "2026-01-01" } })).data.data._id;
    const otherProgram = (await api("POST", "/programs", { token, body: { name: "Other Phased Program", startDate: "2026-01-01" } })).data.data._id;
    const main = (await api("POST", "/projects", { token, body: { program, name: "Water Points", startDate: "2026-01-01", endDate: "2027-12-31", status: "Active" } })).data.data._id;

    const phase = (name, startDate, endDate, extra = {}) =>
        api("POST", "/projects", { token, body: { program: otherProgram, parentProject: main, name, startDate, endDate, status: "Active", ...extra } });

    const one = await phase("Water Points Phase 1", "2026-01-01", "2026-12-31");
    assert.equal(one.status, 201, one.data?.message);
    assert.equal(one.data.data.phaseNumber, 1);
    assert.equal(String(one.data.data.program), program, "a phase is in its main project's program");

    const overlap = await phase("Overlapping", "2026-06-01", "2027-03-31");
    assert.equal(overlap.status, 400);
    assert.match(overlap.data.message, /overlaps Water Points Phase 1/);

    const outside = await phase("Too late", "2027-06-01", "2028-06-30");
    assert.equal(outside.status, 400);
    assert.match(outside.data.message, /inside its main project's dates/);

    const two = await phase("Water Points Phase 2", "2027-01-01", "2027-12-31");
    assert.equal(two.data.data.phaseNumber, 2);

    const nested = await api("POST", "/projects", { token, body: { program, parentProject: one.data.data._id, name: "Phase of a phase", startDate: "2026-02-01", endDate: "2026-03-01" } });
    assert.equal(nested.status, 400);

    // new work goes on a phase
    const activity = (project) => api("POST", "/activities", { token, body: { project, name: "Site survey", activityType: "Assessment", activityDate: "2026-03-01" } });
    const onMain = await activity(main);
    assert.equal(onMain.status, 400);
    assert.match(onMain.data.message, /runs in phases/);
    const onPhase = await activity(one.data.data._id);
    assert.ok(onPhase.status < 300, onPhase.data?.message);

    const budget = (project) => api("POST", "/budgets", { token, body: { level: "project", name: "Budget", project, startYear: 2026, endYear: 2026, lines: [{ category: "Personnel", amounts: yearly({ 2026: 1000 }) }] } });
    assert.equal((await budget(main)).status, 400);
    assert.equal((await budget(one.data.data._id)).status, 201, "each phase has its own budget");

    // a donation for the main project pays for its phases
    const donor = (await api("POST", "/donors", { token, body: { name: "Phases Donor", donorType: "Foundation" } })).data.data._id;
    const donation = (await api("POST", "/donations", { token, body: { donor, title: "Water grant", amount: 50000, currency: "ETB", status: "Received", donationDate: "2026-02-01", fundingRestriction: "Restricted", program, project: main } })).data.data._id;
    const deliver = (project) => create({ program, project, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750, { donor, donation })], beneficiaries: people });
    assert.equal((await deliver(main)).status, 400, "not on the main project");
    const delivered = await deliver(one.data.data._id);
    assert.ok(delivered.status < 300, delivered.data?.message);

    // the main project: its phases, and reports that include them
    const details = (await api("GET", `/projects/${main}`, { token })).data.data;
    assert.deepEqual(details.phases.map(found => found.phaseNumber), [1, 2]);
    const phaseDetails = (await api("GET", `/projects/${one.data.data._id}`, { token })).data.data;
    assert.equal(phaseDetails.parentProject.name, "Water Points");

    const report = (await api("GET", `/report-center/detail/project/${main}?period=all`, { token })).data.data;
    const figure = (label) => report.summary.find(found => found.label === label)?.value;
    assert.equal(figure("Phases"), 2);
    assert.equal(figure("Deliveries"), 1, "the phase's delivery counts for the main project");
    const byPhase = report.sections.find(found => found.key === "phases");
    assert.deepEqual(byPhase.rows.map(row => [row.phase, row.deliveries, row.people]), [["Phase 1", 1, 3], ["Phase 2", 0, 0]]);

    const filtered = (await api("GET", `/report-center/serviceDelivery?period=year&year=2026&project=${main}`, { token })).data.data;
    assert.equal(filtered.summary.find(found => found.label === "Deliveries")?.value, 1, "the main project filter includes its phases");

    // the main project keeps its phases
    assert.equal((await api("DELETE", `/projects/${main}`, { token })).status, 409);
    const shrink = await api("PUT", `/projects/${main}`, { token, body: { endDate: "2027-06-30" } });
    assert.equal(shrink.status, 400);
    assert.match(shrink.data.message, /must hold all its phases/);

});


test("work is dated inside its project: activities, runs and deliveries", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();
    const token = state.tokenA;

    const program = (await api("POST", "/programs", { token, body: { name: "Dated Work Program", startDate: "2026-01-01" } })).data.data._id;
    const project = (await api("POST", "/projects", { token, body: { program, name: "ABC 2026", startDate: "2026-01-01", endDate: "2026-12-31", status: "Active" } })).data.data._id;

    const activity = (activityDate) => api("POST", "/activities", { token, body: { project, name: "Field survey", activityType: "Assessment", activityDate } });

    const before = await activity("2025-06-01");
    assert.equal(before.status, 400);
    assert.match(before.data.message, /outside its project's dates: ABC 2026 runs from 01\/01\/2026 to 31\/12\/2026/);

    const inside = await activity("2026-06-01");
    assert.equal(inside.status, 201, inside.data?.message);
    const activityId = inside.data.data._id;

    // moving the date outside is refused; other edits are fine
    assert.equal((await api("PUT", `/activities/${activityId}`, { token, body: { activityDate: "2027-02-01" } })).status, 400);
    assert.ok((await api("PUT", `/activities/${activityId}`, { token, body: { name: "Field survey (north)" } })).status < 300);

    // an older record dated outside can still be edited for anything else
    await state.db.collection("activities").updateOne({ _id: new mongoose.Types.ObjectId(activityId) }, { $set: { activityDate: new Date("2025-01-01") } });
    const rename = await api("PUT", `/activities/${activityId}`, { token, body: { name: "Field survey (old date)" } });
    assert.ok(rename.status < 300, rename.data?.message);

    // activity runs
    const run = (startDate, endDate) => api("POST", "/activity-runs", { token, body: { activity: activityId, name: "Round 1", startDate, endDate } });
    const lateRun = await run("2026-11-01", "2027-01-15");
    assert.equal(lateRun.status, 400);
    assert.match(lateRun.data.message, /end date .* is outside its project's dates/);
    assert.ok((await run("2026-11-01", "2026-12-15")).status < 300);

    // service deliveries
    const deliver = (deliveryDate) => create({ program, project, deliveryDate, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750)], beneficiaries: people });
    const lateDelivery = await deliver("2025-12-01");
    assert.equal(lateDelivery.status, 400);
    assert.match(lateDelivery.data.message, /delivery date .* is outside its project's dates/);
    assert.ok((await deliver("2026-03-01")).status < 300);

});


test("dates make sense: order, inside the parent, nothing done in the future", { skip }, async () => {

    const token = state.tokenA;
    const { people } = await serviceDeliverySetup();
    const future = new Date(Date.now() + 40 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

    // a program: its end is not before its start; its projects lie inside it
    const program = (await api("POST", "/programs", { token, body: { name: "Dates Program", startDate: "2026-01-01", endDate: "2026-12-31" } })).data.data._id;
    const backwards = await api("PUT", `/programs/${program}`, { token, body: { endDate: "2025-06-30" } });
    assert.equal(backwards.status, 400);

    const outside = await api("POST", "/projects", { token, body: { program, name: "Too long", startDate: "2026-01-01", endDate: "2027-06-30" } });
    assert.equal(outside.status, 400);
    assert.match(outside.data.message, /outside its program's dates: Dates Program runs from 01\/01\/2026 to 31\/12\/2026/);

    const project = (await api("POST", "/projects", { token, body: { program, name: "Dates Project", startDate: "2026-01-01", endDate: "2026-12-31" } })).data.data._id;
    const activity = await api("POST", "/activities", { token, body: { project, name: "Late survey", activityType: "Assessment", activityDate: "2026-09-01" } });
    assert.equal(activity.status, 201, activity.data?.message);

    // the project's dates cannot shrink past its work, nor the program's past its projects
    const shrink = await api("PUT", `/projects/${project}`, { token, body: { endDate: "2026-06-30" } });
    assert.equal(shrink.status, 400);
    assert.match(shrink.data.message, /1 activity\(ies\) of this project is dated outside these dates/);
    const programShrink = await api("PUT", `/programs/${program}`, { token, body: { endDate: "2026-10-31" } });
    assert.equal(programShrink.status, 400);

    // enrollments: inside the program, not before the person was born
    const enroll = (enrollmentDate) => api("POST", "/enrollments", { token, body: { program, beneficiary: people[0], enrollmentDate } });
    const early = await enroll("2025-05-01");
    assert.equal(early.status, 400);
    assert.match(early.data.message, /outside its program's dates/);
    const enrolled = await enroll("2026-02-01");
    assert.ok(enrolled.status < 300, enrolled.data?.message);

    // a date of birth is not in the future or before 1900
    assert.equal((await api("PUT", `/beneficiaries/${people[1]}`, { token, body: { dateOfBirth: "1850-01-01" } })).status, 400);

    // a received donation, an expense: not in the future
    const donor = (await api("POST", "/donors", { token, body: { name: "Dates Donor", donorType: "Foundation" } })).data.data._id;
    const received = await api("POST", "/donations", { token, body: { donor, title: "Tomorrow's grant", amount: 1000, currency: "ETB", status: "Received", donationDate: future } });
    assert.equal(received.status, 400);
    assert.match(received.data.message, /is in the future\. A donation still to come is Pledged\./);
    assert.ok((await api("POST", "/donations", { token, body: { donor, title: "Pledged grant", amount: 1000, currency: "ETB", status: "Pledged", donationDate: future } })).status < 300);

    const line = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data.summary.lines[0];
    const spent = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Next month's rent", amount: 100, currency: "ETB", expenseDate: future });
    assert.equal(spent.status, 400);

    // an enterprise member joins after the enterprise starts
    const enterprise = (await api("POST", "/enterprises", { token, body: { name: "Dates Enterprise", startDate: "2026-03-01" } })).data.data;
    const member = await api("POST", "/enterprise-members", { token, body: { enterprise: enterprise._id, beneficiary: people[2], joinedDate: "2026-01-15" } });
    assert.equal(member.status, 400);
    assert.match(member.data.message, /outside its enterprise's dates/);

});


test("currencies: one list (CHF included); others are refused; CHF converts like the rest", { skip }, async () => {

    const token = state.tokenA;
    const donor = (await api("POST", "/donors", { token, body: { name: "Swiss Foundation", donorType: "Foundation" } })).data.data._id;

    // a Swiss franc donation, with its rate on the day it was received
    const chf = await api("POST", "/donations", { token, body: { donor, title: "Swiss grant", amount: 10000, currency: "CHF", status: "Received", donationDate: "2026-04-01", receivedRate: 140 } });
    assert.ok(chf.status < 300, chf.data?.message);
    const funding = (await api("GET", `/donations/${chf.data.data._id}`, { token })).data.data.funding;
    assert.equal(funding.currency, "CHF");
    assert.equal(funding.inBase.received, 1400000);

    // a code that is not in the list
    const unknown = await api("POST", "/donations", { token, body: { donor, title: "Odd grant", amount: 10, currency: "XYZ", status: "Pledged", donationDate: "2026-04-01" } });
    assert.equal(unknown.status, 400);
    assert.match(unknown.data.message, /ETB, USD, EUR, GBP, CHF/);

    // an expense paid in CHF on the ETB budget: converted at its rate
    const line = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data.summary.lines[0];
    const noRate = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Swiss consultant", amount: 100, currency: "CHF" });
    assert.equal(noRate.status, 400);
    const paid = await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Swiss consultant", amount: 100, currency: "CHF", exchangeRate: 140 });
    assert.ok(paid.status < 300, paid.data?.message);
    assert.equal(paid.data.data.budgetAmount, 14000);
    assert.equal((await newExpense(state.dataEntryToken, { budgetLine: line._id, description: "Odd", amount: 1, currency: "XYZ", exchangeRate: 2 })).status, 400);

});


test("an item's donor is its donation's donor; a project report shows the budget of its period", { skip }, async () => {

    const { token, people, item, create } = await serviceDeliverySetup();

    const donorA = (await api("POST", "/donors", { token, body: { name: "Donor A", donorType: "Foundation" } })).data.data._id;
    const donorB = (await api("POST", "/donors", { token, body: { name: "Donor B", donorType: "Foundation" } })).data.data._id;
    const donation = (await api("POST", "/donations", { token, body: { donor: donorA, title: "A's grant", amount: 100000, currency: "ETB", status: "Received", donationDate: "2026-03-01", fundingRestriction: "Unrestricted" } })).data.data._id;

    // only the donation: the donor is filled in
    const saved = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750, { donation })], beneficiaries: people });
    assert.ok(saved.status < 300, saved.data?.message);
    const delivery = (await api("GET", `/service-deliveries/${saved.data.data._id}`, { token })).data.data;
    assert.equal(String(delivery.items[0].donor?._id || delivery.items[0].donor), donorA);

    // another donor than the donation's: refused
    const wrong = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750, { donation, donor: donorB })], beneficiaries: people });
    assert.equal(wrong.status, 400);
    assert.match(wrong.data.message, /from another donor/);

    // the budget of project one covers 2026-2027: FY 2020 has none, FY 2026 its own year
    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    const project = String(budget.project?._id || budget.project);
    const field = (report, pattern) => report.record.fields.find(entry => pattern.test(entry.label));
    const fy2020 = (await api("GET", `/report-center/detail/project/${project}?period=year&year=2020`, { token })).data.data;
    assert.match(field(fy2020, /Budget for FY 2020/).value, /None/);
    const fy2026 = (await api("GET", `/report-center/detail/project/${project}?period=year&year=2026`, { token })).data.data;
    assert.ok(field(fy2026, /Approved budget for FY 2026/), "the FY 2026 budget is shown");
    assert.ok(fy2026.summary.some(entry => entry.label === "Spent in the period"));

});


test("codes never collide; an attendance sheet saved from an old copy is refused", { skip }, async () => {

    const { people } = await serviceDeliverySetup();
    const token = state.tokenA;

    const program = (await api("POST", "/programs", { token, body: { name: "Codes Program", startDate: "2026-01-01" } })).data.data._id;

    // three projects, activities and runs created at the same moment get different codes
    const projects = await Promise.all([1, 2, 3].map(n => api("POST", "/projects", { token, body: { program, name: `Same moment ${n}`, startDate: "2026-01-01", endDate: "2026-12-31" } })));
    assert.ok(projects.every(res => res.status === 201), projects.map(res => res.data?.message).join(" | "));
    assert.equal(new Set(projects.map(res => res.data.data.projectCode)).size, 3);

    const project = projects[0].data.data._id;
    const activities = await Promise.all([1, 2, 3].map(n => api("POST", "/activities", { token, body: { project, name: `Parallel activity ${n}`, activityType: "Training", activityDate: "2026-03-01" } })));
    assert.ok(activities.every(res => res.status === 201), activities.map(res => res.data?.message).join(" | "));
    assert.equal(new Set(activities.map(res => res.data.data.activityCode)).size, 3);

    const activity = activities[0].data.data._id;
    const runs = await Promise.all([1, 2, 3].map(n => api("POST", "/activity-runs", { token, body: { activity, name: `Batch ${n}`, startDate: "2026-03-01", endDate: "2026-03-05" } })));
    assert.ok(runs.every(res => res.status < 300), runs.map(res => res.data?.message).join(" | "));
    assert.equal(new Set(runs.map(res => res.data.data.runCode)).size, 3);

    // an attendance sheet
    const session = (await api("POST", "/attendance", { token, body: { activityRun: runs[0].data.data._id, sessionTitle: "Day 1", sessionNumber: 1, sessionDate: "2026-03-01" } })).data.data;
    const row = (beneficiary, status = "Present") => ({ participantType: "Beneficiary", beneficiary, gender: "Female", ageGroup: "Adult", status });
    const save = (body) => api("POST", `/attendance/${session._id}/records`, { token, body });

    const first = await save({ records: [row(people[0]), row(people[1])], version: 0 });
    assert.equal(first.status, 200, first.data?.message);
    assert.equal(first.data.version, 1);

    // a second person still has the sheet as it was (version 0): refused, nothing lost
    const stale = await save({ records: [row(people[2])], version: 0 });
    assert.equal(stale.status, 409);
    assert.match(stale.data.message, /Someone else saved this attendance sheet/);
    const records = async () => (await api("GET", `/attendance/${session._id}/records`, { token })).data.data;
    assert.equal((await records()).length, 2);

    // "add" keeps the people already on the sheet
    const added = await save({ mode: "add", records: [row(people[1]), row(people[2]), { participantType: "Government", gender: "Male", ageGroup: "Adult", status: "Present", externalParticipant: { name: "Woreda expert", organizationName: "Woreda office", position: "Expert" } }] });
    assert.equal(added.status, 200, added.data?.message);
    const after = await records();
    assert.equal(after.length, 4, "2 kept + 1 new beneficiary + 1 government (the repeated one is not added twice)");

});


test("custom roles: the admin makes a role; its users can do exactly what it allows", { skip }, async () => {

    const token = state.tokenA;

    // a role: programs and projects (view + create), reports
    const made = await api("POST", "/roles", { token, body: { name: "Program Manager", description: "Runs programs and projects", permissions: ["program.create", "project.create", "report.read"] } });
    assert.equal(made.status, 201, made.data?.message);
    assert.ok(made.data.data.permissions.includes("program.read"), "seeing what you may create is added");

    // names and permissions are checked
    assert.equal((await api("POST", "/roles", { token, body: { name: "program manager", permissions: [] } })).status, 409);
    assert.equal((await api("POST", "/roles", { token, body: { name: "Viewer", permissions: [] } })).status, 409);
    assert.equal((await api("POST", "/roles", { token, body: { name: "Platform", permissions: ["plan.update"] } })).status, 400);

    // a user with the role
    const user = await api("POST", "/users", { token, body: { name: "Meron PM", email: "pm@test.local", password: "ProgMgr2026x", customRole: made.data.data._id, mustChangePassword: false } });
    assert.ok(user.status < 300, user.data?.message);
    const login = (await api("POST", "/auth/login", { body: { email: "pm@test.local", password: "ProgMgr2026x" } })).data.data;
    assert.equal(login.user.roleName, "Program Manager");
    assert.ok(login.user.permissions.includes("program.create"));
    const pm = login.token;

    assert.equal((await api("POST", "/programs", { token: pm, body: { name: "PM's program", startDate: "2026-01-01" } })).status, 201);
    assert.equal((await api("GET", "/beneficiaries", { token: pm })).status, 403, "not in the role");
    assert.equal((await api("POST", "/budgets", { token: pm, body: { level: "program", name: "x", program: state.adminAId, startYear: 2026, endYear: 2026 } })).status, 403);

    // the role changes: so do its users' permissions
    assert.ok((await api("PUT", `/roles/${made.data.data._id}`, { token, body: { permissions: ["program.create", "project.create", "report.read", "beneficiary.read"] } })).status < 300);
    assert.equal((await api("GET", "/beneficiaries", { token: pm })).status, 200);

    // the roles list shows it with its user; it cannot be deleted while used
    const roles = (await api("GET", "/roles", { token })).data.data;
    assert.equal(roles.custom.find(role => role.name === "Program Manager").users, 1);
    assert.ok(roles.builtIn.some(role => role.key === "finance_officer"));
    assert.ok(roles.catalog.some(group => group.module === "budget"));
    assert.equal((await api("DELETE", `/roles/${made.data.data._id}`, { token })).status, 409);

    // other organizations do not see it; only admins manage roles
    assert.equal((await api("GET", "/roles", { token: state.tokenB })).data.data.custom.length, 0);
    assert.equal((await api("POST", "/roles", { token: pm, body: { name: "Mine", permissions: [] } })).status, 403);

});


test("wording: an organization's own words reach reports and role names", { skip }, async () => {

    const token = state.tokenA;

    const saved = await api("PUT", "/terminology", { token, body: { terms: { donation: { singular: "Fund", plural: "Funds" }, organizationAdmin: { singular: "Administrator", plural: "Administrators" } } } });
    assert.equal(saved.status, 200, saved.data?.message);
    assert.equal(saved.data.data.find(term => term.key === "donation").own.singular, "Fund");

    // reports (and so their exports) use them
    const donors = (await api("GET", "/report-center/donors?period=year&year=2026", { token })).data.data;
    assert.ok(donors.summary.some(item => item.label === "Funds in the period"), donors.summary.map(item => item.label).join(" | "));
    assert.ok(!JSON.stringify(donors.summary.map(item => item.label)).includes("Donation"));
    const catalog = (await api("GET", "/report-center", { token })).data.data;
    assert.ok(Array.isArray(catalog) && !JSON.stringify(catalog).includes("Donation"), "the catalog uses the words too");

    // role names
    const roles = (await api("GET", "/roles", { token })).data.data;
    assert.equal(roles.builtIn.find(role => role.key === "organization_admin").name, "Administrator");

    // other organizations keep their words; only admins change them
    assert.equal((await api("GET", "/terminology", { token: state.tokenB })).data.data.find(term => term.key === "donation").own, null);
    assert.equal((await api("PUT", "/terminology", { token: state.dataEntryToken, body: { terms: { donation: { singular: "Gift" } } } })).status, 403);
    assert.equal((await api("PUT", "/terminology", { token, body: { terms: { unknownThing: { singular: "x" } } } })).status, 400);

    // back to the defaults
    const reset = await api("PUT", "/terminology", { token, body: { terms: { donation: null, organizationAdmin: { singular: "", plural: "" } } } });
    assert.equal(reset.status, 200);
    assert.ok(reset.data.data.every(term => term.own === null));

});


test("statuses: one lifecycle for work; what a status allows", { skip }, async () => {

    const { people, item, create } = await serviceDeliverySetup();
    const token = state.tokenA;

    const program = (await api("POST", "/programs", { token, body: { name: "Status Program", startDate: "2026-01-01", status: "Active" } })).data.data._id;
    const newProject = (name, status) => api("POST", "/projects", { token, body: { program, name, startDate: "2026-01-01", endDate: "2026-12-31", ...(status ? { status } : {}) } });

    // one lifecycle: new projects are Planned; older values are read as their new ones
    assert.equal((await newProject("Plain")).data.data.status, "Planned");
    assert.equal((await newProject("Old draft", "Draft")).data.data.status, "Planned");
    const project = (await newProject("Status Project", "Active")).data.data._id;
    const activity = await api("POST", "/activities", { token, body: { project, name: "Old ongoing", activityType: "Training", activityDate: "2026-03-01", status: "Ongoing" } });
    assert.equal(activity.data.data.status, "Active");

    // Completed: no new plans, late records still allowed
    assert.ok((await api("PUT", `/projects/${project}`, { token, body: { status: "Completed" } })).status < 300);
    const plan = await api("POST", "/activities", { token, body: { project, name: "Too late", activityType: "Training", activityDate: "2026-04-01" } });
    assert.equal(plan.status, 400);
    assert.match(plan.data.message, /is Completed/);
    const late = await create({ program, project, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750)], beneficiaries: people });
    assert.ok(late.status < 300, late.data?.message);

    // Suspended / Cancelled: nothing new
    assert.ok((await api("PUT", `/projects/${project}`, { token, body: { status: "Suspended" } })).status < 300);
    const paused = await create({ program, project, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 2, 750)], beneficiaries: people });
    assert.equal(paused.status, 400);
    assert.match(paused.data.message, /is Suspended/);

    // an Inactive beneficiary or donor receives nothing new
    const person = (await api("POST", "/beneficiaries", { token, body: { firstName: "Inactive", lastName: "Person", gender: (await api("GET", "/lookups/module/Beneficiary/category/Gender", { token })).data.data[0]._id, dateOfBirth: "1990-01-01", phone: "0912999001" } })).data.data._id;
    assert.ok((await api("PUT", `/beneficiaries/${person}`, { token, body: { status: "Inactive" } })).status < 300);
    const toInactive = await create({ program, recipientType: "Individual", allocationMethod: "Shared", items: [item("Hygiene Kit", "Set", 1, 750)], beneficiaries: [person] });
    assert.equal(toInactive.status, 400);
    assert.match(toInactive.data.message, /Inactive and cannot receive new services/);
    assert.equal((await api("POST", "/enrollments", { token, body: { program, beneficiary: person, enrollmentDate: "2026-02-01" } })).status, 400);

    const donor = (await api("POST", "/donors", { token, body: { name: "Gone Donor", donorType: "Foundation", status: "Inactive" } })).data.data._id;
    const gift = await api("POST", "/donations", { token, body: { donor, title: "Late gift", amount: 100, currency: "ETB", status: "Received", donationDate: "2026-03-01" } });
    assert.equal(gift.status, 400);
    assert.match(gift.data.message, /donor .* is Inactive/);

    // the organization renames a status label: reports show it, the value stays
    assert.ok((await api("PUT", "/terminology", { token, body: { terms: { statusSuspended: { singular: "On hold" } } } })).status < 300);
    const report = await api("GET", "/report-center/programs?period=all", { token });
    const shown = report.data.data.details.rows.find(row => row.name === "Status Project");
    assert.equal(shown?.status, "On hold");
    assert.equal((await api("GET", `/projects/${project}`, { token })).data.data.status, "Suspended");
    await api("PUT", "/terminology", { token, body: { terms: { statusSuspended: null } } });

});


test("projects and activities move to another parent only while nothing is recorded under them", { skip }, async () => {

    const token = state.tokenA;
    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token })).data.data;
    const projectOne = String(budget.project?._id || budget.project);
    const otherProgram = (await api("POST", "/programs", { token, body: { name: "Move Target Program", startDate: "2026-01-01" } })).data.data._id;

    const used = await api("PUT", `/projects/${projectOne}`, { token, body: { program: otherProgram } });
    assert.equal(used.status, 409);
    assert.match(used.data.message, /1 budget/);

    const fresh = (await api("POST", "/projects", { token, body: { program: String(budget.program?._id || budget.program), name: "Empty Project", startDate: "2026-01-01", endDate: "2026-12-31" } })).data.data._id;
    const moved = await api("PUT", `/projects/${fresh}`, { token, body: { program: otherProgram } });
    assert.equal(moved.status, 200, moved.data?.message);
    assert.equal(String(moved.data.data.program?._id || moved.data.data.program), otherProgram);

});


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
// ETB CASH PAID FROM A FOREIGN DONATION
// =====================================================

test("service delivery: ETB cash paid from a USD donation is charged at the donation's rate", { skip }, async () => {

    const { token, item, create, people } = await serviceDeliverySetup();
    const donor = (await api("POST", "/donors", { token, body: { name: "Dollar Foundation", donorType: "Foundation" } })).data.data._id;
    const usd = (await api("POST", "/donations", { token, body: { donor, title: "USD cash grant", amount: 1000, currency: "USD", status: "Received", donationDate: "2026-03-01", receivedRate: 150 } })).data.data._id;
    const funding = async (id) => (await api("GET", `/donations/${id}`, { token })).data.data.funding;
    const cash = (amount, extra = {}) => item("Cash Assistance", "ETB", 1, amount, { donor, donation: usd, ...extra });

    // ETB 15,000 at the received rate (150) = USD 100
    const first = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(15000)], beneficiaries: people });
    assert.ok(first.status < 300, first.data?.message);
    assert.equal(first.data.data.items[0].donationRate, 150);
    assert.equal((await funding(usd)).byDeliveries, 100);

    // a rate given on the item: ETB 10,000 at 100 = USD 100
    const second = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(10000, { donationRate: 100 })], beneficiaries: people });
    assert.ok(second.status < 300, second.data?.message);
    assert.equal((await funding(usd)).byDeliveries, 200);

    // more than is left (USD 800): refused in USD
    const tooMuch = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(150000)], beneficiaries: people });
    assert.equal(tooMuch.status, 400);
    assert.match(tooMuch.data.message, /has USD 800\.00 left/);

    // a USD pledge has no rate yet: the item must give one
    const pledge = (await api("POST", "/donations", { token, body: { donor, title: "USD pledge", amount: 500, currency: "USD", status: "Pledged", donationDate: "2026-03-01" } })).data.data._id;
    const noRate = await create({ recipientType: "Individual", allocationMethod: "Shared", items: [cash(1500, { donation: pledge })], beneficiaries: people });
    assert.equal(noRate.status, 400);
    assert.match(noRate.data.message, /give the exchange rate \(1 USD = \? ETB\)/);

});


// =====================================================
// MODULES SWITCHED PER ORGANIZATION BY THE SUPER ADMIN
// =====================================================

test("modules: the super admin switches modules off and on per organization; off is hidden, not deleted", { skip }, async () => {

    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token: state.tokenA })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId || me.user?.organizationId);
    const tors = (await api("GET", "/tors", { token: state.tokenA })).data.data;
    const torCount = (Array.isArray(tors) ? tors : tors.items || []).length;

    // only the super admin manages modules
    assert.equal((await api("GET", `/admin/organizations/${orgA}/modules`, { token: state.tokenA })).status, 403);
    const list = (await api("GET", `/admin/organizations/${orgA}/modules`, { token: sa })).data.data;
    assert.ok(list.modules.every(module => module.enabled || ["me", "procurement", "humanitarian"].includes(module.key)), "all on at first, except new modules (M&E, procurement, humanitarian)");
    assert.equal(list.modules.find(module => module.key === "me").enabled, false);

    // TOR and funding off
    const off = await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { tor: false, funding: false } } });
    assert.equal(off.status, 200);
    assert.equal(off.data.data.modules.find(module => module.key === "tor").enabled, false);

    const admin = (await api("GET", "/auth/me", { token: state.tokenA })).data.data;
    const permissions = admin.permissions || admin.user?.permissions || [];
    assert.ok(!permissions.some(permission => permission.startsWith("tor.") || permission.startsWith("donation.")), "their permissions are left out");
    assert.ok(!(admin.modules || admin.user?.modules).includes("funding"));
    assert.equal((await api("GET", "/tors", { token: state.tokenA })).status, 403);
    assert.equal((await api("GET", "/donations", { token: state.tokenA })).status, 403);
    const catalog = (await api("GET", "/report-center", { token: state.tokenA })).data.data.map(report => report.key);
    assert.ok(!catalog.includes("donors") && catalog.includes("beneficiaries"));
    assert.equal((await api("GET", "/report-center/donors?period=year&year=2026", { token: state.tokenA })).status, 403);

    // TOR off: data entry creates activities directly
    const dataEntry = (await api("GET", "/auth/me", { token: state.dataEntryToken })).data.data;
    assert.ok((dataEntry.permissions || dataEntry.user?.permissions).includes("activity.create"));

    // another organization is not affected
    assert.equal((await api("GET", "/tors", { token: state.tokenB })).status, 200);

    // on again: everything is back, nothing was deleted
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { tor: true, funding: true } } });
    const back = (await api("GET", "/tors", { token: state.tokenA })).data.data;
    assert.equal((Array.isArray(back) ? back : back.items || []).length, torCount);
    assert.equal((await api("GET", "/donations", { token: state.tokenA })).status, 200);

});


// =====================================================
// M&E: INDICATORS (module "me", off until switched on)
// =====================================================

test("M&E: indicators with targets; entered and automatic actuals; progress and the indicators report", { skip }, async () => {

    const token = state.tokenA;
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);

    // a new module: off until the platform admin switches it on
    assert.equal((await api("GET", "/indicators", { token })).status, 403);
    assert.equal((await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { me: true } } })).status, 200);
    assert.equal((await api("GET", "/indicators", { token })).status, 200);

    await serviceDeliverySetup();
    const programs = (await api("GET", `/programs?search=${encodeURIComponent("Service Delivery Test Program")}`, { token })).data.data;
    const program = (Array.isArray(programs) ? programs : programs.items)[0]._id;

    // entered: quarterly targets, values per quarter
    const manual = await api("POST", "/indicators", {
        token,
        body: {
            program, level: "Outcome", result: "Households earn more", name: "Households with improved income",
            unit: "number", frequency: "Quarterly", source: "manual", baseline: { value: 10, date: "2026-01-01" },
            targets: [{ period: "2026-Q1", value: 50 }, { period: "2026-Q2", value: 60 }]
        }
    });
    assert.equal(manual.status, 201, manual.data?.message);
    assert.match(manual.data.data.code, /^IND-\d{6}$/);
    const manualId = manual.data.data._id;

    assert.equal((await api("PUT", `/indicators/${manualId}/values/2026-Q1`, { token, body: { value: 45, female: 30, male: 15 } })).status, 200);
    const both = await api("PUT", `/indicators/${manualId}/values/2026-Q2`, { token, body: { value: 30 } });
    const rows = both.data.data.progress.rows;
    assert.equal(rows.find(row => row.period === "2026-Q1").percent, 90);
    assert.equal(rows.find(row => row.period === "2026-Q1").status, "On track");
    assert.equal(rows.find(row => row.period === "2026-Q2").status, "Off track");

    // the wrong kind of period, a future one, a bad split
    assert.equal((await api("PUT", `/indicators/${manualId}/values/2026`, { token, body: { value: 5 } })).status, 400);
    assert.equal((await api("PUT", `/indicators/${manualId}/values/2030-Q1`, { token, body: { value: 5 } })).status, 400);
    assert.equal((await api("PUT", `/indicators/${manualId}/values/2026-Q3`, { token, body: { value: 5, female: 4, male: 4 } })).status, 400);

    // a percentage target above 100 is refused
    assert.equal((await api("POST", "/indicators", { token, body: { program, level: "Output", name: "Too much", unit: "percent", frequency: "Annual", source: "manual", targets: [{ period: "2026", value: 120 }] } })).status, 400);

    // automatic: the same figure as the service delivery report
    const auto = await api("POST", "/indicators", {
        token,
        body: { program, level: "Output", name: "People reached", frequency: "Annual", source: "auto", measure: "beneficiariesReached", targets: [{ period: "2026", value: 10 }] }
    });
    assert.equal(auto.status, 201, auto.data?.message);
    const report = (await api("GET", `/report-center/serviceDelivery?period=year&year=2026&program=${program}`, { token })).data.data;
    const reached = report.summary.find(item => item.label === "Beneficiaries reached").value;
    assert.equal(auto.data.data.progress.rows.find(row => row.period === "2026").actual, reached);
    // its values cannot be typed
    assert.equal((await api("PUT", `/indicators/${auto.data.data._id}/values/2026`, { token, body: { value: 1 } })).status, 400);

    // the indicators report: Q1 + Q2 targets (110) against 75 entered
    const year = (await api("GET", `/report-center/indicators?period=year&year=2026&program=${program}`, { token })).data.data;
    const row = year.sections.find(item => item.key === "indicators").rows.find(item => item.name === "Households with improved income");
    assert.equal(row.target, 110);
    assert.equal(row.actual, 75);

    // data entry enters values but does not create indicators
    assert.equal((await api("POST", "/indicators", { token: state.dataEntryToken, body: { program, level: "Output", name: "x", frequency: "Annual", source: "manual" } })).status, 403);
    assert.equal((await api("PUT", `/indicators/${manualId}/values/2026-Q3`, { token: state.dataEntryToken, body: { value: 55 } })).status, 200);

    // the organization's own limits: Q2 is 50% achieved (30 of 60)
    const q2Status = async () => (await api("GET", `/indicators/${manualId}`, { token })).data.data.progress.rows.find(item => item.period === "2026-Q2").status;
    assert.equal(await q2Status(), "Off track");
    assert.deepEqual((await api("GET", "/indicators/settings", { token })).data.data.defaults, { onTrack: 90, atRisk: 60 });
    assert.equal((await api("PUT", "/indicators/settings", { token, body: { onTrack: 50, atRisk: 80 } })).status, 400);
    assert.equal((await api("PUT", "/indicators/settings", { token: state.dataEntryToken, body: { onTrack: 80, atRisk: 50 } })).status, 403);
    const own = await api("PUT", "/indicators/settings", { token, body: { onTrack: 80, atRisk: 50 } });
    assert.equal(own.status, 200);
    assert.equal(own.data.data.onTrack, 80);
    assert.equal(await q2Status(), "At risk");
    // back to the defaults
    assert.equal((await api("PUT", "/indicators/settings", { token, body: { reset: true } })).data.data.onTrack, 90);
    assert.equal(await q2Status(), "Off track");

    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { me: false } } });

});


// =====================================================
// PROCUREMENT: SUPPLIERS AND PURCHASE REQUESTS
// (module "procurement", off until switched on)
// =====================================================

test("procurement: suppliers; purchase requests commit budget money only within what the line has left", { skip }, async () => {

    const admin = state.tokenA;
    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token: admin })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);

    // a new module: off until the platform admin switches it on
    assert.equal((await api("GET", "/purchase-requests", { token: de })).status, 403);
    assert.equal((await api("GET", "/suppliers", { token: fin })).status, 403);
    const on = await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: true } } });
    assert.equal(on.data.data.modules.find(module => module.key === "procurement").enabled, true);

    // ---------------- suppliers
    assert.equal((await api("POST", "/suppliers", { token: de, body: { name: "Abebe Stationery" } })).status, 403, "data entry only reads suppliers");
    const supplier = await api("POST", "/suppliers", { token: fin, body: { name: "Abebe Stationery", categories: ["Goods"], tin: "0012345678", phone: "0911000000" } });
    assert.equal(supplier.status, 201, supplier.data?.message);
    assert.match(supplier.data.data.supplierCode, /^SUP-\d{6}$/);
    const supplierId = supplier.data.data._id;
    assert.equal((await api("POST", "/suppliers", { token: fin, body: { name: "abebe stationery" } })).status, 409, "a name once");
    assert.equal((await api("PUT", `/suppliers/${supplierId}`, { token: fin, body: { status: "Blacklisted" } })).status, 400, "blacklisting needs a reason");

    // ---------------- a request on Personnel (budget one, FY 2026)
    const position = async () => (await lineOf(de, state.budgetOneId, "Personnel")).line.amounts.find(item => item.fiscalYear === 2026);
    const before = await position();
    const { line: personnel } = await lineOf(de, state.budgetOneId, "Personnel");
    const newRequest = (body) =>
        api("POST", "/purchase-requests", { token: de, body: { budget: state.budgetOneId, budgetLine: personnel._id, requestDate: "2026-04-01", title: "Laptops for field staff", ...body } });

    assert.equal((await newRequest({ items: [] })).status, 400, "at least one item");
    const created = await newRequest({
        suggestedSupplier: supplierId,
        items: [
            { description: "Laptop", unit: "pcs", quantity: 2, unitPrice: 8000 },
            { description: "Laptop bag", unit: "pcs", quantity: 2, unitPrice: 2000 }
        ]
    });
    assert.equal(created.status, 201, created.data?.message);
    const request = created.data.data;
    assert.match(request.requestCode, /^PR-\d{6}$/);
    assert.equal(request.status, "Draft");
    assert.equal(request.estimatedTotal, 20000);
    assert.equal(request.items[0].total, 16000);
    assert.equal(request.fiscalYear, 2026);
    assert.equal(request.category, "Personnel");
    assert.equal(request.line.available, before.remaining);

    // a draft reserves nothing
    assert.equal((await position()).committed, 0);

    // more than the line has left: saved, but not submitted
    const tooBig = await newRequest({ title: "Vehicle", items: [{ description: "Pick-up", quantity: 1, unitPrice: before.remaining + 1000 }] });
    assert.equal(tooBig.status, 201);
    assert.equal(tooBig.data.data.line.overBudget, true, "the form can warn");
    const refused = await api("POST", `/purchase-requests/${tooBig.data.data._id}/submit`, { token: de });
    assert.equal(refused.status, 400);
    assert.equal(refused.data.errors?.[0]?.code, "OVER_BUDGET");
    assert.equal((await api("DELETE", `/purchase-requests/${tooBig.data.data._id}`, { token: de })).status, 200);

    // submit -> approve: the estimate is committed
    assert.equal((await api("POST", `/purchase-requests/${request._id}/submit`, { token: de })).status, 200);
    assert.equal((await api("POST", `/purchase-requests/${request._id}/approve`, { token: de, body: {} })).status, 403, "data entry cannot approve");
    const approved = await api("POST", `/purchase-requests/${request._id}/approve`, { token: fin, body: {} });
    assert.equal(approved.status, 200, approved.data?.message);
    assert.equal(approved.data.data.status, "Approved");
    let year = await position();
    assert.equal(year.committed, 20000);
    assert.equal(year.remaining, before.remaining - 20000, "Remaining = Budget - Committed - Spent");
    const budget = (await api("GET", `/budgets/${state.budgetOneId}`, { token: de })).data.data;
    assert.ok(budget.summary.totalCommitted >= 20000);

    // approved requests are locked; the requester was told
    assert.equal((await api("PUT", `/purchase-requests/${request._id}`, { token: de, body: { title: "Changed" } })).status, 409);
    assert.equal((await api("DELETE", `/purchase-requests/${request._id}`, { token: de })).status, 409);
    const told = (await api("GET", "/notifications", { token: de })).data.data;
    assert.ok((told.items || told.notifications || told).some(item => /Purchase request approved/.test(item.title)));

    // a direct expense now sees the committed money
    const expense = await newExpense(de, { budgetLine: personnel._id, description: "Consultant, all that is left", amount: before.remaining - 10000 });
    assert.equal(expense.status, 201, expense.data?.message);
    assert.equal(expense.data.data.line.committed, 20000);
    assert.equal(expense.data.data.line.overBudget, true);
    await api("DELETE", `/expenses/${expense.data.data._id}`, { token: de });

    // return needs a comment; reject is final
    const second = await newRequest({ title: "Printer toner", items: [{ description: "Toner", quantity: 4, unitPrice: 1500 }] });
    await api("POST", `/purchase-requests/${second.data.data._id}/submit`, { token: de });
    assert.equal((await api("POST", `/purchase-requests/${second.data.data._id}/reject`, { token: fin, body: {} })).status, 400);
    const rejected = await api("POST", `/purchase-requests/${second.data.data._id}/reject`, { token: fin, body: { comment: "Bought centrally" } });
    assert.equal(rejected.data.data.status, "Rejected");
    assert.equal((await api("POST", `/purchase-requests/${second.data.data._id}/submit`, { token: de })).status, 409);

    // a supplier in use is not deleted; an inactive one is not offered
    assert.equal((await api("DELETE", `/suppliers/${supplierId}`, { token: fin })).status, 409);
    assert.equal((await api("PUT", `/suppliers/${supplierId}`, { token: fin, body: { status: "Inactive" } })).status, 200);
    assert.equal((await newRequest({ suggestedSupplier: supplierId, items: [{ description: "Pens", quantity: 10, unitPrice: 20 }] })).status, 400);
    assert.ok(!(await api("GET", "/suppliers/options", { token: de })).data.data.some(item => item._id === supplierId));

    // cancelling an approved request releases its money (with a reason)
    assert.equal((await api("POST", `/purchase-requests/${request._id}/cancel`, { token: fin, body: {} })).status, 400);
    const cancelled = await api("POST", `/purchase-requests/${request._id}/cancel`, { token: fin, body: { comment: "Donor sent laptops" } });
    assert.equal(cancelled.data.data.status, "Cancelled");
    year = await position();
    assert.equal(year.committed, 0);
    assert.equal(year.remaining, before.remaining);

    // the list
    const list = await api("GET", "/purchase-requests?status=Cancelled", { token: de });
    assert.equal(list.data.data.length, 1);
    assert.equal(list.data.data[0].itemCount, 2);

    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: false } } });
    assert.equal((await api("GET", "/purchase-requests", { token: de })).status, 403);

});


test("procurement: methods by amount; quotations, bid analysis by an approver or a committee; purchase orders commit the real price", { skip }, async () => {

    const admin = state.tokenA;
    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token: admin })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: true } } });

    // ---------------- the organization's limits
    const defaults = (await api("GET", "/procurement/settings", { token: de })).data.data;
    assert.equal(defaults.methods.direct.upTo, 50000);
    assert.equal(defaults.methods.tender.committee, true);
    assert.equal((await api("PUT", "/procurement/settings", { token: fin, body: { methods: { direct: { upTo: 10000 } } } })).status, 403, "only the organization admin");
    assert.equal((await api("PUT", "/procurement/settings", { token: admin, body: { methods: { direct: { upTo: 400000 } } } })).status, 400, "direct must stay below RFQ");
    const set = await api("PUT", "/procurement/settings", { token: admin, body: { methods: { direct: { upTo: 5000 }, rfq: { upTo: 20000 } } } });
    assert.equal(set.status, 200, set.data?.message);
    assert.equal(set.data.data.methods.rfq.upTo, 20000);

    // ---------------- suppliers and a committee
    const supplierIds = [];
    for (const name of ["Alpha Computers", "Beta Tech", "Gamma Trading"]) {
        supplierIds.push((await api("POST", "/suppliers", { token: fin, body: { name } })).data.data._id);
    }
    const people = (await api("GET", "/procurement/committees/members", { token: fin })).data.data;
    const idOfUser = (email) => people.find(person => person.email === email)._id;
    assert.equal((await api("POST", "/procurement/committees", { token: de, body: { name: "Tender Committee" } })).status, 403);
    assert.equal((await api("POST", "/procurement/committees", { token: admin, body: { name: "Tender Committee", members: [{ user: idOfUser("admin-a@test.local") }], approvalsNeeded: 2 } })).status, 400, "not more approvals than members");
    const committee = await api("POST", "/procurement/committees", {
        token: admin,
        body: { name: "Tender Committee", members: [{ user: idOfUser("admin-a@test.local"), role: "Chair" }, { user: idOfUser("finance@test.local") }], approvalsNeeded: 2 }
    });
    assert.equal(committee.status, 201, committee.data?.message);
    const committeeId = committee.data.data._id;

    // ---------------- a 24,000 request: above RFQ (20,000) -> tender with a committee
    const position = async () => (await lineOf(de, state.budgetOneId, "Personnel")).line.amounts.find(item => item.fiscalYear === 2026);
    const before = await position();
    const { line: personnel } = await lineOf(de, state.budgetOneId, "Personnel");
    const newApproved = async (title, items) => {
        const made = await api("POST", "/purchase-requests", { token: de, body: { budget: state.budgetOneId, budgetLine: personnel._id, requestDate: "2026-05-02", title, items } });
        assert.equal(made.status, 201, made.data?.message);
        const sent = await api("POST", `/purchase-requests/${made.data.data._id}/submit`, { token: de });
        assert.equal(sent.status, 200, sent.data?.message);
        assert.equal((await api("POST", `/purchase-requests/${made.data.data._id}/approve`, { token: fin, body: {} })).status, 200);
        return made.data.data;
    };
    const request = await newApproved("Laptops", [{ description: "Laptop", quantity: 2, unitPrice: 12000 }]);
    const itemId = request.items[0]._id;
    const pr = (path) => `/purchase-requests/${request._id}${path}`;

    assert.equal((await api("POST", pr("/quotes"), { token: fin, body: {} })).status, 409, "start first");
    const started = await api("POST", pr("/sourcing/start"), { token: fin, body: {} });
    assert.equal(started.status, 200, started.data?.message);
    assert.equal(started.data.data.sourcing.method, "tender");
    assert.equal(started.data.data.sourcing.minQuotes, 3);
    assert.equal(started.data.data.sourcing.needsCommittee, true);

    assert.equal((await api("POST", pr("/quotes"), { token: fin, body: { supplier: supplierIds[0], items: [] } })).status, 400, "a price for every item");
    const first = await api("POST", pr("/quotes"), { token: fin, body: { supplier: supplierIds[0], reference: "Q-11", items: [{ item: itemId, unitPrice: 11500 }], deliveryDays: 5 } });
    assert.equal(first.status, 201, first.data?.message);
    assert.equal(first.data.data.sourcing.quotes[0].total, 23000);
    assert.equal((await api("POST", pr("/quotes"), { token: fin, body: { supplier: supplierIds[0], items: [{ item: itemId, unitPrice: 1 }] } })).status, 409, "one quotation per supplier");
    const second = await api("POST", pr("/quotes"), { token: fin, body: { supplier: supplierIds[1], items: [{ item: itemId, unitPrice: 10500 }] } });
    const [quoteAlpha, quoteBeta] = second.data.data.sourcing.quotes;
    assert.equal(quoteBeta.total, 21000);

    // Alpha is not the lowest: a reason; only 2 of 3 quotes: a reason; a tender: a committee
    await api("PUT", pr("/sourcing"), { token: fin, body: { selectedQuote: quoteAlpha._id } });
    assert.match((await api("POST", pr("/sourcing/submit"), { token: fin })).data.message, /not the lowest/);
    await api("PUT", pr("/sourcing"), { token: fin, body: { selectionReason: "Beta cannot deliver before the training" } });
    assert.match((await api("POST", pr("/sourcing/submit"), { token: fin })).data.message, /at least 3 quotations/);
    await api("PUT", pr("/sourcing"), { token: fin, body: { fewerQuotesReason: "Only two suppliers in the region" } });
    assert.match((await api("POST", pr("/sourcing/submit"), { token: fin })).data.message, /committee/i);
    assert.equal((await api("PUT", pr("/sourcing"), { token: fin, body: { committee: committeeId } })).status, 200);
    const submitted = await api("POST", pr("/sourcing/submit"), { token: fin });
    assert.equal(submitted.status, 200, submitted.data?.message);
    assert.equal(submitted.data.data.sourcing.panel.length, 2);

    // the committee decides; nobody else
    assert.equal((await api("DELETE", `/procurement/committees/${committeeId}`, { token: admin })).status, 409, "a decision is waiting");
    assert.equal((await api("POST", pr("/sourcing/approve"), { token: fin, body: {} })).status, 409, "its members approve it");
    assert.equal((await api("POST", pr("/sourcing/decision"), { token: de, body: { decision: "Approve" } })).status, 403, "not a member");
    assert.equal((await api("GET", "/procurement/waiting-for-me", { token: fin })).data.data.length, 1);
    const one = await api("POST", pr("/sourcing/decision"), { token: admin, body: { decision: "Approve" } });
    assert.equal(one.data.data.sourcing.status, "Submitted", "1 of 2 needed");
    assert.equal((await api("POST", pr("/sourcing/decision"), { token: admin, body: { decision: "Approve" } })).status, 409, "once");
    assert.equal((await api("POST", pr("/sourcing/decision"), { token: fin, body: { decision: "Object" } })).status, 400, "an objection needs a reason");
    const two = await api("POST", pr("/sourcing/decision"), { token: fin, body: { decision: "Approve", comment: "Delivery matters" } });
    assert.equal(two.status, 200, two.data?.message);
    assert.equal(two.data.data.sourcing.status, "Approved");

    // still the estimate committed until the order is issued
    assert.equal((await position()).committed, 24000);

    // ---------------- the purchase order: the real price is committed
    assert.equal((await api("POST", pr("/purchase-order"), { token: de, body: {} })).status, 403);
    const issued = await api("POST", pr("/purchase-order"), { token: fin, body: { paymentTerms: "30 days after delivery" } });
    assert.equal(issued.status, 201, issued.data?.message);
    const order = issued.data.data;
    assert.match(order.poCode, /^PO-\d{6}$/);
    assert.equal(order.total, 23000);
    assert.equal(order.supplier.name, "Alpha Computers");
    assert.equal(order.items[0].unitPrice, 11500);
    assert.ok(order.deliveryDate, "from the quoted delivery time");
    assert.equal((await api("GET", pr(""), { token: de })).data.data.status, "Ordered");
    let year = await position();
    assert.equal(year.committed, 23000);
    assert.equal(year.remaining, before.remaining - 23000);
    assert.equal((await api("POST", pr("/purchase-order"), { token: fin, body: {} })).status, 409, "one order per request");
    assert.equal((await api("POST", pr("/cancel"), { token: fin, body: { comment: "Not needed" } })).status, 409, "cancel the order first");

    const pdf = await fetch(`${BASE}/purchase-orders/${order._id}/pdf`, { headers: { Authorization: `Bearer ${de}` } });
    assert.equal(pdf.status, 200);
    assert.match(pdf.headers.get("content-type"), /pdf/);
    assert.equal((await pdf.arrayBuffer()).byteLength > 1000, true);
    assert.equal((await api("GET", "/purchase-orders?search=Alpha", { token: de })).data.data.length, 1);

    // cancelling the order gives the request back to choose again
    const cancelled = await api("POST", `/purchase-orders/${order._id}/cancel`, { token: fin, body: { comment: "Supplier out of stock" } });
    assert.equal(cancelled.data.data.status, "Cancelled");
    const back = (await api("GET", pr(""), { token: de })).data.data;
    assert.equal(back.status, "Approved");
    assert.equal(back.sourcing.status, "Draft");
    assert.equal((await position()).committed, 24000, "the estimate again");
    await api("POST", pr("/cancel"), { token: fin, body: { comment: "Bought by the donor" } });
    assert.equal((await position()).committed, 0);

    // ---------------- a 4,000 request: direct purchase, one approver
    const small = await newApproved("Toner", [{ description: "Toner", quantity: 4, unitPrice: 1000 }]);
    const sp = (path) => `/purchase-requests/${small._id}${path}`;
    const direct = (await api("POST", sp("/sourcing/start"), { token: fin, body: {} })).data.data.sourcing;
    assert.equal(direct.method, "direct");
    assert.equal(direct.needsCommittee, false);
    const quoted = await api("POST", sp("/quotes"), { token: fin, body: { supplier: supplierIds[2], items: [{ item: small.items[0]._id, unitPrice: 950 }] } });
    await api("PUT", sp("/sourcing"), { token: fin, body: { selectedQuote: quoted.data.data.sourcing.quotes[0]._id } });
    assert.equal((await api("POST", sp("/sourcing/submit"), { token: fin })).status, 200);
    assert.equal((await api("POST", sp("/sourcing/return"), { token: fin, body: {} })).status, 400, "returning needs a comment");
    assert.equal((await api("POST", sp("/sourcing/return"), { token: fin, body: { comment: "Add the quotation number" } })).data.data.sourcing.status, "Returned");
    await api("PUT", sp(`/quotes/${quoted.data.data.sourcing.quotes[0]._id}`), { token: fin, body: { reference: "INV-55" } });
    await api("POST", sp("/sourcing/submit"), { token: fin });
    assert.equal((await api("POST", sp("/sourcing/approve"), { token: de, body: {} })).status, 403);
    assert.equal((await api("POST", sp("/sourcing/approve"), { token: admin, body: {} })).data.data.sourcing.status, "Approved");
    const smallOrder = (await api("POST", sp("/purchase-order"), { token: fin, body: {} })).data.data;
    assert.equal(smallOrder.total, 3800);
    state.smallOrder = smallOrder;
    state.smallRequest = small._id;
    assert.equal((await position()).committed, 3800);

    // back to the defaults
    assert.equal((await api("PUT", "/procurement/settings", { token: admin, body: { reset: true } })).data.data.methods.direct.upTo, 50000);
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: false } } });

});


test("procurement: goods received (partial, rejected); payments are expenses that move Committed to Spent; the order closes when received and paid", { skip }, async () => {

    const admin = state.tokenA;
    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token: admin })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: true } } });

    // the order from the last test: 4 toner at 950 = 3,800, all committed
    const po = (path = "") => `/purchase-orders/${state.smallOrder._id}${path}`;
    const tonerItem = state.smallOrder.items[0]._id;
    const position = async () => (await lineOf(de, state.budgetOneId, "Personnel")).line.amounts.find(item => item.fiscalYear === 2026);
    const before = await position();
    assert.equal(before.committed, 3800);

    assert.equal((await api("POST", po("/payments"), { token: fin, body: {} })).status, 409, "nothing received yet");

    // ---------------- goods received: 3 accepted, 1 rejected
    assert.equal((await api("POST", po("/receipts"), { token: de, body: { lines: [{ item: tonerItem, accepted: 5 }] } })).status, 400, "only 4 ordered");
    assert.equal((await api("POST", po("/receipts"), { token: de, body: { lines: [{ item: tonerItem, accepted: 3, rejected: 1 }] } })).status, 400, "a rejection needs a remark");
    const grn = await api("POST", po("/receipts"), { token: de, body: { deliveryNote: "DN-77", lines: [{ item: tonerItem, accepted: 3, rejected: 1, remark: "Box damaged" }] } });
    assert.equal(grn.status, 201, grn.data?.message);
    let order = grn.data.data;
    assert.equal(order.status, "Partially Received");
    assert.equal(order.fulfilment.receivedValue, 2850);
    assert.equal(order.fulfilment.payable, 2850);
    assert.match(order.fulfilment.receipts[0].grnCode, /^GRN-\d{6}$/);
    assert.equal((await api("POST", po("/cancel"), { token: fin, body: { comment: "Changed our mind" } })).status, 409, "goods were received");

    // ---------------- payment 1: what was received
    assert.equal((await api("POST", po("/payments"), { token: fin, body: { amount: 3000 } })).status, 400, "only what was received");
    const pay1 = await api("POST", po("/payments"), { token: fin, body: { referenceNumber: "INV-9001" } });
    assert.equal(pay1.status, 201, pay1.data?.message);
    assert.equal(pay1.data.data.amount, 2850);
    assert.equal(pay1.data.data.source, "procurement");
    assert.equal(pay1.data.data.status, "Draft");
    assert.equal(pay1.data.data.line.overBudget, false, "the order's own committed money pays it");
    assert.equal((await api("POST", po("/payments"), { token: fin, body: {} })).status, 400, "the rest is waiting for approval");
    assert.equal((await api("PUT", `/expenses/${pay1.data.data._id}`, { token: fin, body: { amount: 2900 } })).status, 400, "not more than received");
    assert.equal((await api("POST", `/purchase-orders/receipts/${order.fulfilment.receipts[0]._id}/cancel`, { token: fin, body: { comment: "Counted wrong" } })).status, 409, "the goods are being paid");

    await api("POST", `/expenses/${pay1.data.data._id}/submit`, { token: fin });
    const approved1 = await api("POST", `/expenses/${pay1.data.data._id}/approve`, { token: admin, body: {} });
    assert.equal(approved1.status, 200, approved1.data?.message);
    let year = await position();
    assert.equal(year.committed, 950, "Committed -> Spent");
    assert.equal(year.spent, before.spent + 2850);
    assert.equal(year.remaining, before.remaining, "remaining does not change when committed money is spent");

    // ---------------- the last toner arrives and is paid: the order closes itself
    order = (await api("POST", po("/receipts"), { token: de, body: { lines: [{ item: tonerItem, accepted: 1 }] } })).data.data;
    assert.equal(order.status, "Received");
    assert.equal((await api("POST", po("/close"), { token: fin, body: { comment: "Enough" } })).status, 409, "950 received and not paid");
    const pay2 = (await api("POST", po("/payments"), { token: fin, body: {} })).data.data;
    assert.equal(pay2.amount, 950);
    await api("POST", `/expenses/${pay2._id}/submit`, { token: fin });
    assert.equal((await api("POST", `/expenses/${pay2._id}/approve`, { token: admin, body: {} })).status, 200);
    order = (await api("GET", po(), { token: de })).data.data;
    assert.equal(order.status, "Closed");
    assert.equal(order.paidTotal, 3800);
    assert.equal((await api("GET", `/purchase-requests/${state.smallRequest}`, { token: de })).data.data.status, "Closed");
    year = await position();
    assert.equal(year.committed, 0);
    assert.equal(year.spent, before.spent + 3800);

    // voiding a payment opens the order again
    await api("POST", `/expenses/${pay2._id}/void`, { token: admin, body: { comment: "Paid twice by mistake" } });
    order = (await api("GET", po(), { token: de })).data.data;
    assert.equal(order.status, "Received");
    assert.equal(order.fulfilment.payable, 950);
    assert.equal((await api("GET", `/purchase-requests/${state.smallRequest}`, { token: de })).data.data.status, "Ordered");
    assert.equal((await position()).committed, 950);

    // ---------------- the goods received note as a PDF
    const grnPdf = await fetch(`${BASE}/purchase-orders/receipts/${order.fulfilment.receipts[0]._id}/pdf`, { headers: { Authorization: `Bearer ${de}` } });
    assert.equal(grnPdf.status, 200);
    assert.match(grnPdf.headers.get("content-type"), /pdf/);

    // ---------------- the procurement report
    const catalog = (await api("GET", "/report-center", { token: de })).data.data.map(report => report.key);
    assert.ok(catalog.includes("procurement"));
    const report = await api("GET", "/report-center/procurement?period=year&year=2026", { token: de });
    assert.equal(report.status, 200, report.data?.message);
    const sectionOf = (key) => report.data.data.sections.find(item => item?.key === key);
    const gamma = sectionOf("suppliers").rows.find(row => row.label === "Gamma Trading");
    assert.equal(gamma.ordered, 3800);
    assert.equal(gamma.received, 3800);
    assert.equal(gamma.paid, 2850, "the voided payment does not count");
    assert.ok(!sectionOf("suppliers").rows.some(row => row.label === "Alpha Computers"), "a cancelled order is not spend");
    const open = sectionOf("open").rows.find(row => row.code === state.smallOrder.poCode);
    assert.equal(open.toPay, 950);
    assert.equal(open.flag, "Received, not paid");
    const excel = await fetch(`${BASE}/report-center/procurement?period=year&year=2026&format=excel`, { headers: { Authorization: `Bearer ${de}` } });
    assert.equal(excel.status, 200);

    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: false } } });
    assert.ok(!(await api("GET", "/report-center", { token: de })).data.data.some(report => report.key === "procurement"), "module off: report hidden");

});


// =====================================================
// PROJECT TYPES (Development, Humanitarian, Emergency ...)
// =====================================================

test("project types: each organization's own list; a program mixes types; phases follow their main project; lists and reports filter by type", { skip }, async () => {

    const token = state.tokenA;

    // a new organization gets the common types (Lookups > Projects > Project Type)
    const types = (await api("GET", "/lookups/module/Project/category/ProjectType", { token })).data.data;
    const typeId = (value) => types.find(type => type.value === value)?._id;
    assert.ok(typeId("Development") && typeId("Humanitarian") && typeId("Emergency"), types.map(type => type.value).join(", "));

    // an emergency project in the same program as development projects
    const flood = await api("POST", "/projects", { token, body: { program: state.budgetProgramId, name: "Flood Response", projectType: "Emergency", startDate: "2026-08-01", endDate: "2026-12-31" } });
    assert.equal(flood.status < 300, true, flood.data?.message);
    assert.equal(String(flood.data.data.projectType), String(typeId("Emergency")));
    const wrong = await api("POST", "/projects", { token, body: { program: state.budgetProgramId, name: "Wrong Type", projectType: "Space Mission", startDate: "2026-08-01", endDate: "2026-12-31" } });
    assert.ok(wrong.status >= 400 && wrong.status < 500, "a type not in the list is refused");

    // a phase takes its main project's type
    const phase = await api("POST", "/projects", { token, body: { program: state.budgetProgramId, parentProject: flood.data.data._id, name: "Flood Response Phase 1", projectType: "Development", startDate: "2026-08-01", endDate: "2026-09-30" } });
    assert.equal(phase.status < 300, true, phase.data?.message);
    assert.equal(String(phase.data.data.projectType), String(typeId("Emergency")));

    // the list filters by type and shows it
    const emergency = (await api("GET", `/projects?projectType=${typeId("Emergency")}&limit=50`, { token })).data.data;
    assert.deepEqual(emergency.map(project => project.name).sort(), ["Flood Response", "Flood Response Phase 1"]);
    assert.equal(emergency[0].projectType.value, "Emergency");

    // changing the main project's type moves its phases along
    await api("PUT", `/projects/${flood.data.data._id}`, { token, body: { projectType: typeId("Humanitarian") } });
    const after = (await api("GET", `/projects/${phase.data.data._id}`, { token })).data.data;
    assert.equal(after.projectType.value, "Humanitarian");

    // reports: only the projects of that type
    const all = (await api("GET", "/report-center/budgets?period=year&year=2026", { token })).data.data;
    const humanitarian = (await api("GET", `/report-center/budgets?period=year&year=2026&projectType=${typeId("Humanitarian")}`, { token })).data.data;
    assert.ok(all.details.rows.length > 0);
    assert.equal(humanitarian.details.rows.length, 0, "the flood projects have no budget yet");
    const development = (await api("GET", `/report-center/budgets?period=year&year=2026&projectType=${typeId("Development")}`, { token })).data.data;
    assert.equal(development.details.rows.length, 0, "no project is Development yet");

});


test("emergency procurement: projects of an emergency type need fewer quotations and may order before the approval, which follows; the report lists them", { skip }, async () => {

    const admin = state.tokenA;
    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token: admin })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: true } } });

    const rule = (await api("GET", "/procurement/settings", { token: de })).data.data.emergency;
    assert.equal(rule.enabled, true);
    assert.equal(rule.minQuotes, 1);
    assert.equal(rule.afterPurchase, true);

    // budget one's project becomes an Emergency project
    const types = (await api("GET", "/lookups/module/Project/category/ProjectType", { token: admin })).data.data;
    const emergencyType = types.find(type => type.value === "Emergency")._id;
    assert.equal((await api("PUT", `/projects/${state.projectOne}`, { token: admin, body: { projectType: emergencyType } })).status, 200);

    const { line: personnel } = await lineOf(de, state.budgetOneId, "Personnel");
    const made = await api("POST", "/purchase-requests", { token: de, body: { budget: state.budgetOneId, budgetLine: personnel._id, requestDate: "2026-06-01", title: "Water tanks for flood victims", items: [{ description: "Water tank 1000 L", quantity: 1, unitPrice: 2000 }] } });
    assert.equal(made.status, 201, made.data?.message);
    const pr = (path = "") => `/purchase-requests/${made.data.data._id}${path}`;
    await api("POST", pr("/submit"), { token: de });
    await api("POST", pr("/approve"), { token: fin, body: {} });

    // emergency procurement, whatever the amount
    const started = (await api("POST", pr("/sourcing/start"), { token: fin, body: {} })).data.data.sourcing;
    assert.equal(started.method, "emergency");
    assert.equal(started.minQuotes, 1);
    assert.equal(started.needsCommittee, false);
    assert.equal(started.afterPurchase, true);

    const supplier = (await api("POST", "/suppliers", { token: fin, body: { name: "Delta Plastics" } })).data.data._id;
    const quoted = await api("POST", pr("/quotes"), { token: fin, body: { supplier, items: [{ item: made.data.data.items[0]._id, unitPrice: 1900 }] } });
    await api("PUT", pr("/sourcing"), { token: fin, body: { selectedQuote: quoted.data.data.sourcing.quotes[0]._id } });
    assert.match((await api("POST", pr("/sourcing/submit"), { token: fin })).data.message, /emergency/i, "a reason is needed");
    await api("PUT", pr("/sourcing"), { token: fin, body: { emergencyReason: "Flood on 28 May; families without water" } });
    assert.equal((await api("POST", pr("/sourcing/submit"), { token: fin })).status, 200);

    // the order before the approval
    const order = await api("POST", pr("/purchase-order"), { token: fin, body: {} });
    assert.equal(order.status, 201, order.data?.message);
    let request = (await api("GET", pr(), { token: de })).data.data;
    assert.equal(request.status, "Ordered");
    assert.equal(request.sourcing.orderedBeforeApproval, true);
    assert.equal(request.sourcing.status, "Submitted");

    // the approval follows (it cannot be returned any more)
    assert.equal((await api("POST", pr("/sourcing/return"), { token: fin, body: { comment: "Too expensive" } })).status, 409);
    const approved = await api("POST", pr("/sourcing/approve"), { token: admin, body: { comment: "Agreed, emergency" } });
    assert.equal(approved.status, 200, approved.data?.message);
    assert.equal(approved.data.data.sourcing.status, "Approved");

    // an exception in the procurement report
    const report = (await api("GET", "/report-center/procurement?period=year&year=2026", { token: de })).data.data;
    const exception = report.sections.find(item => item?.key === "exceptions").rows.find(row => row.code === order.data.data.poCode);
    assert.equal(exception.issue, "Emergency procurement");
    assert.match(exception.detail, /ordered before approval \(approved since\)/);
    assert.match(exception.reason, /Flood/);

    // the organization can switch the rule off
    assert.equal((await api("PUT", "/procurement/settings", { token: admin, body: { emergency: { enabled: false } } })).data.data.emergency.enabled, false);
    await api("PUT", "/procurement/settings", { token: admin, body: { reset: true } });

    await api("PUT", `/projects/${state.projectOne}`, { token: admin, body: { projectType: null } });
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { procurement: false } } });

});


// =====================================================
// HUMANITARIAN RESPONSE (module "humanitarian")
// =====================================================

test("humanitarian: the same person does not get the same service twice in the period unless confirmed with a reason; 3W/4W report", { skip }, async () => {

    const { token, item, create, shares, people } = await serviceDeliverySetup();
    const sa = (await login("sa@test.local", "SuperTest2026x")).data.data.token;
    const me = (await api("GET", "/auth/me", { token })).data.data;
    const orgA = String(me.organizationId?._id || me.organizationId);

    const kitsFor = (date, extra = {}) => {
        const kits = item("Hygiene Kit", "Set", 3, 750);
        return create({ deliveryDate: date, recipientType: "Individual", allocationMethod: "Individual", items: [kits], beneficiaries: shares(kits, 1, 750), ...extra });
    };

    // a new module: off until switched on (no check, no settings, no report)
    assert.equal((await api("GET", "/humanitarian/settings", { token })).status, 403);
    assert.equal((await kitsFor("2026-09-01")).status < 300, true);
    assert.equal((await kitsFor("2026-09-02")).status < 300, true, "off: no duplicate check");
    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { humanitarian: true } } });

    const settings = (await api("GET", "/humanitarian/settings", { token })).data.data.duplicateCheck;
    assert.equal(settings.enabled, true);
    assert.equal(settings.period, "month");

    // the same month: refused, with who and when
    const again = await kitsFor("2026-09-20");
    assert.equal(again.status, 409, again.data?.message);
    assert.equal(again.data.errors.length >= 3, true);
    assert.equal(again.data.errors[0].code, "DUPLICATE_DELIVERY");
    assert.match(again.data.message, /already received the same service in the same month/);

    // confirmed: a reason is needed, then it is saved and marked
    assert.equal((await kitsFor("2026-09-20", { confirmDuplicates: true })).status, 400);
    const confirmed = await kitsFor("2026-09-20", { confirmDuplicates: true, duplicateReason: "Second kit for newborns" });
    assert.equal(confirmed.status < 300, true, confirmed.data?.message);
    assert.equal(confirmed.data.data.duplicateConfirmed, true);

    // another month is fine; a cancelled delivery does not count
    assert.equal((await kitsFor("2026-10-02")).status < 300, true);
    assert.equal((await kitsFor("2026-10-05", { status: "Cancelled" })).status < 300, true);

    // the organization's own period: within 30 days
    const days = await api("PUT", "/humanitarian/settings", { token, body: { duplicateCheck: { period: "days", days: 30 } } });
    assert.equal(days.data.data.duplicateCheck.period, "days");
    assert.equal((await kitsFor("2026-10-20")).status, 409, "18 days after 2 October");
    assert.equal((await api("PUT", "/humanitarian/settings", { token: state.dataEntryToken, body: { reset: true } })).status, 403, "only the organization admin");
    await api("PUT", "/humanitarian/settings", { token, body: { reset: true } });

    // household size on a person (quick registration)
    const genders = (await api("GET", "/lookups/module/Beneficiary/category/Gender", { token })).data.data;
    const quick = await api("POST", "/beneficiaries", { token, body: { firstName: "Zewdu", lastName: "Alemu", gender: genders.find(g => g.value === "Male")._id, dateOfBirth: "1986-07-01", householdSize: 6, woreda: "Fogera" } });
    assert.equal(quick.status < 300, true, quick.data?.message);
    assert.equal(quick.data.data.householdSize, 6);

    // the 3W / 4W report
    const catalog = (await api("GET", "/report-center", { token })).data.data.map(report => report.key);
    assert.ok(catalog.includes("threeW"));
    const report = await api("GET", "/report-center/threeW?period=month&year=2026&month=9", { token });
    assert.equal(report.status, 200, report.data?.message);
    const summary = Object.fromEntries(report.data.data.summary.map(item => [item.label, item.value]));
    assert.equal(summary["People reached"], people.length);
    assert.equal(summary.Women, people.length, "the three test people are adult women");
    assert.equal(summary["Repeated deliveries (confirmed)"], 1);
    const row = report.data.data.details.rows.find(item => item.activity === "Hygiene Kit");
    assert.equal(row.sector.length > 0, true);
    assert.equal(row.people, people.length, "counted once per row");
    assert.equal(row.deliveries, 3);
    const excel = await fetch(`${BASE}/report-center/threeW?period=month&year=2026&month=9&format=excel`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(excel.status, 200);

    await api("PUT", `/admin/organizations/${orgA}/modules`, { token: sa, body: { modules: { humanitarian: false } } });
    assert.ok(!(await api("GET", "/report-center", { token })).data.data.some(report => report.key === "threeW"));

});


// =====================================================
// ENROLLMENT PER PROJECT (or phase)
// =====================================================

test("enrollment: per project or phase (the program comes from it); once per project; a person in several projects of a program; older ones get their project", { skip }, async () => {

    const token = state.tokenA;
    const genders = (await api("GET", "/lookups/module/Beneficiary/category/Gender", { token })).data.data;
    const person = async (firstName) =>
        (await api("POST", "/beneficiaries", { token, body: { firstName, lastName: "Enrolled", gender: genders[0]._id, dateOfBirth: "1990-01-01" } })).data.data._id;

    const program = (await api("POST", "/programs", { token, body: { name: "Enrollment Program", startDate: "2026-01-01" } })).data.data._id;
    const otherProgram = (await api("POST", "/programs", { token, body: { name: "Other Enrollment Program", startDate: "2026-01-01" } })).data.data._id;
    const project = async (name, extra = {}) => {
        const made = await api("POST", "/projects", { token, body: { program: extra.program || program, name, startDate: "2026-02-01", endDate: "2026-12-31", ...extra } });
        assert.equal(made.status < 300, true, made.data?.message);
        return made.data.data._id;
    };
    const single = await project("Literacy Classes");
    const main = await project("Food Response");
    const phase1 = await project("Food Response Phase 1", { parentProject: main, endDate: "2026-06-30" });
    const phase2 = await project("Food Response Phase 2", { parentProject: main, startDate: "2026-07-01" });
    const elsewhere = await project("Elsewhere", { program: otherProgram });

    const almaz = await person("Almaz");
    const enroll = (body) => api("POST", "/enrollments", { token, body: { status: "Active", enrollmentDate: "2026-03-01", ...body } });

    // the project decides the program
    const first = await enroll({ project: single, beneficiary: almaz });
    assert.equal(first.status < 300, true, first.data?.message);
    assert.equal(String(first.data.data.program._id || first.data.data.program), program);
    assert.equal(first.data.data.project.name, "Literacy Classes");

    // once per project; several projects (phases) of one program are fine
    assert.equal((await enroll({ project: single, beneficiary: almaz })).status, 409);
    assert.equal((await enroll({ project: phase1, beneficiary: almaz })).status < 300, true);
    assert.equal((await enroll({ project: phase2, beneficiary: almaz, enrollmentDate: "2026-07-05" })).status < 300, true, "the same person in the next phase");

    // a main project with phases: its phases enroll
    assert.match((await enroll({ project: main, beneficiary: await person("Hana") })).data.message, /phases/);
    // inside the project's dates; a project of another program is refused
    assert.equal((await enroll({ project: single, beneficiary: await person("Kebede"), enrollmentDate: "2026-01-15" })).status, 400);
    assert.equal((await enroll({ project: elsewhere, program, beneficiary: await person("Selam") })).status, 400);

    // the main project lists the people of its phases
    const ofMain = (await api("GET", `/enrollments?project=${main}&limit=50`, { token })).data;
    assert.equal((ofMain.data || ofMain).length, 2);

    // an older enrollment (program only) gets its project later
    const tsegaye = await person("Tsegaye");
    const older = await enroll({ program, beneficiary: tsegaye });
    assert.equal(older.status < 300, true, older.data?.message);
    const none = (await api("GET", `/enrollments?project=none&program=${program}`, { token })).data;
    assert.equal((none.data || none).length, 1);
    assert.equal((await api("PUT", `/enrollments/${older.data.data._id}`, { token, body: { project: elsewhere } })).status, 400, "another program");
    assert.equal((await api("PUT", `/enrollments/${older.data.data._id}`, { token, body: { project: single } })).status < 300, true);

});


// =====================================================
// PASSWORDS: OWN AT FIRST SIGN-IN, THEN THE ADMIN MANAGES
// =====================================================

test("passwords: a new user chooses their own at first sign-in; after that only the admin resets it", { skip }, async () => {

    const created = await api("POST", "/users", { token: state.tokenA, body: { name: "First Login", email: "firstlogin@test.local", password: "Given2026x", role: "viewer" } });
    assert.ok(created.status < 300, created.data?.message);
    const userId = created.data.data._id || created.data.data.id;

    // first sign-in: asked to choose their own, nothing else works
    const first = await login("firstlogin@test.local", "Given2026x");
    assert.equal(first.data.data.user.mustChangePassword, true);
    assert.equal((await api("GET", "/programs", { token: first.data.data.token })).data.code, "PASSWORD_CHANGE_REQUIRED");
    const own = await api("POST", "/auth/change-password", { token: first.data.data.token, body: { currentPassword: "Given2026x", newPassword: "Mine2026x" } });
    assert.equal(own.status, 200);

    // after that: no changing it themselves
    const again = await api("POST", "/auth/change-password", { token: own.data.data.token, body: { currentPassword: "Mine2026x", newPassword: "Other2026x" } });
    assert.equal(again.status, 403);
    assert.match(again.data.message, /organization administrator/);

    // forgotten: the admin resets it, and the user chooses a new one again
    const reset = await api("POST", `/users/${userId}/reset-password`, { token: state.tokenA });
    assert.equal(reset.status, 200);
    const afterReset = await login("firstlogin@test.local", reset.data.data.temporaryPassword);
    assert.equal(afterReset.data.data.user.mustChangePassword, true);

    // an admin cannot reset their own password
    const me = (await api("GET", "/auth/me", { token: state.tokenA })).data.data;
    const self = await api("POST", `/users/${me.id || me._id || me.user?.id}/reset-password`, { token: state.tokenA });
    assert.equal(self.status, 400);

});


// =====================================================
// NOTIFICATIONS: APPROVERS AND SUBMITTERS ARE TOLD
// =====================================================

test("notifications: approvers told of what waits, submitters of the decision; everyone reads their own", { skip }, async () => {

    const de = state.dataEntryToken;
    const fin = state.financeToken;
    const notes = async (token, query = "") => (await api("GET", `/notifications${query}`, { token })).data.data;

    // data entry has no notification permission, but reads their own
    assert.equal((await api("GET", "/notifications/unread-count", { token: de })).status, 200);
    await api("PATCH", "/notifications/read-all", { token: de });
    await api("PATCH", "/notifications/read-all", { token: fin });

    const { line } = await lineOf(de, state.budgetOneId, "Personnel");
    const expense = (await newExpense(de, { budgetLine: line._id, description: "Notified expense", payee: "Shop", amount: 10 })).data.data;
    assert.equal((await api("POST", `/expenses/${expense._id}/submit`, { token: de })).status, 200);

    // the finance officer (an approver) is told, with a link to it
    const waiting = (await notes(fin, "?unread=true")).notifications.find(note => note.title === "Expense waiting for approval" && note.message.includes("Notified expense"));
    assert.ok(waiting, "approver notified");
    assert.equal(waiting.type, "approval");
    assert.equal(waiting.link, `/expenses/${expense._id}`);
    // not the person who submitted it
    assert.ok(!(await notes(de)).notifications.some(note => note.title === "Expense waiting for approval" && note.message.includes("Notified expense")));

    // returned: the submitter is told
    assert.equal((await api("POST", `/expenses/${expense._id}/return`, { token: fin, body: { comment: "Add the receipt" } })).status, 200);
    const mine = await notes(de, "?unread=true");
    const returned = mine.notifications.find(note => note.title === "Expense returned for changes");
    assert.ok(returned, "submitter notified");
    assert.match(returned.message, /Add the receipt/);
    assert.ok(mine.unread >= 1);

    // read one, then all
    assert.equal((await api("PATCH", `/notifications/${returned._id}/read`, { token: de })).status, 200);
    await api("PATCH", "/notifications/read-all", { token: de });
    assert.equal((await api("GET", "/notifications/unread-count", { token: de })).data.data.unread, 0);

    // someone else's notification cannot be marked read
    assert.equal((await api("PATCH", `/notifications/${waiting._id}/read`, { token: de })).status, 404);

    await api("DELETE", `/expenses/${expense._id}`, { token: de });

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
