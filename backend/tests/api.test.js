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

    assert.equal(categories.length, 12, `got: ${categories.join(", ")}`);

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
    assert.equal(year2026.allocated, 600100, "600,000 + 100 (draft budgets count too)");
    assert.equal(year2026.unallocated, 399900);

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
        body: { name: "Finance Officer", email: "finance@test.local", password: "Finance2026x", role: "finance_officer" }
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

test("reports: budget vs actual and spending by donor", { skip }, async () => {

    const fin = state.financeToken;

    const bva = await api("GET", "/reports/budgetVsActualReport?period=annual&year=2026", { token: fin });
    assert.equal(bva.status, 200, bva.data?.message);
    assert.equal(bva.data.data.summary.fiscalYear, "FY 2026");
    assert.equal(bva.data.data.summary.totalSpent, 300000);
    assert.equal(bva.data.data.summary.totalBudget, 600000);
    assert.equal(bva.data.data.summary.percentSpent, 50);

    const personnel = bva.data.data.details.find(row => row.category === "Personnel");
    assert.equal(personnel.spent, 150000);
    assert.equal(personnel.remaining, 250000);

    const donors = await api("GET", "/reports/donorSpendingReport?period=annual&year=2026", { token: fin });
    assert.equal(donors.status, 200, donors.data?.message);
    assert.equal(donors.data.data.summary.approvedExpenses, 2);
    assert.equal(donors.data.data.summary.expensesNotLinked, 2);

    // Other organizations see none of it
    const other = await api("GET", "/reports/budgetVsActualReport?period=annual&year=2026", { token: state.tokenB });
    assert.equal(other.status, 200);
    assert.equal(other.data.data.summary.projectBudgets, 0);

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

    // Project report reads the Budgets module too
    const report = await api("GET", "/reports/projectReport?period=annual&year=2026", { token });
    assert.equal(report.status, 200, report.data?.message);
    const row = report.data.data.details.find(item => item.name === "Budget Project One");
    assert.equal(row.budgetStatus, "Approved");
    assert.equal(row.approvedBudget, "ETB 1,100,000.00");
    assert.equal(row.spent, "ETB 300,000.00");
    assert.equal(report.data.data.details.find(item => item.name === "Typed Budget Project").budgetStatus, "No budget");
    assert.equal(report.data.data.summary.totalApprovedBudget, "ETB 1,100,000.00");

    // Dashboard: approved program budgets per currency
    const dashboard = await api("GET", "/reports/dashboardReport?period=annual&year=2026", { token });
    assert.equal(dashboard.status, 200, dashboard.data?.message);
    assert.equal(dashboard.data.data.statistics.budget.byCurrency.ETB, 3000000);

});


test("free plan: 5 users (admin + 4), the 6th is refused", { skip }, async () => {

    // Organization B is on the Free plan with only its admin
    for (let i = 1; i <= 4; i++) {
        const res = await api("POST", "/users", {
            token: state.tokenB,
            body: { name: `Free User ${i}`, email: `free${i}@test.local`, password: "FreeUser2026x", role: i === 1 ? "finance_officer" : "data_entry" }
        });
        assert.ok(res.status < 300, `user ${i}: ${res.status} ${res.data?.message}`);
    }

    const sixth = await api("POST", "/users", {
        token: state.tokenB,
        body: { name: "Free User 5", email: "free5@test.local", password: "FreeUser2026x", role: "viewer" }
    });
    assert.ok(sixth.status >= 400 && sixth.status < 500, `6th user: ${sixth.status}`);

});


test("funding: received only, never added across currencies", { skip }, async () => {

    const token = state.tokenB;

    const donor = await api("POST", "/donors", { token, body: { name: "Currency Test Donor", donorType: "Foundation" } });
    assert.ok(donor.status < 300, donor.data?.message);

    const donation = (title, amount, currency, status) =>
        api("POST", "/donations", {
            token,
            body: { donor: donor.data.data._id, title, amount, currency, status, donationDate: "2026-03-01" }
        });

    assert.ok((await donation("ETB grant", 1000000, "ETB", "Received")).status < 300);
    assert.ok((await donation("EUR grant", 5000, "EUR", "Received")).status < 300);
    assert.ok((await donation("ETB pledge", 300000, "ETB", "Pledged")).status < 300);

    const dashboard = await api("GET", "/dashboard?period=annual&year=2026", { token });
    assert.equal(dashboard.status, 200, dashboard.data?.message);
    assert.equal(dashboard.data.data.summary.totalFunding, 1000000, "ETB received only");
    assert.deepEqual(dashboard.data.data.summary.fundingByCurrency, { ETB: 1000000, EUR: 5000 });

    const financial = await api("GET", "/reports/financialReport?period=annual&year=2026", { token });
    assert.equal(financial.data.data.summary.totalReceived, "ETB 1,000,000.00 + EUR 5,000.00");

    const donors = await api("GET", "/reports/donorReport?period=annual&year=2026", { token });
    assert.equal(donors.data.data.summary.totalPledged, "ETB 300,000.00");

});


test("reports: attendance summary and donor impact generate (were 500)", { skip }, async () => {

    // attendanceSummaryReport had markdown fences in the code;
    // donorImpactReport used old field names and crashed on
    // donations without a program.
    for (const report of ["attendanceSummaryReport", "donorImpactReport"]) {
        const res = await api("GET", `/reports/${report}?period=annual&year=2026`, { token: state.tokenA });
        assert.equal(res.status, 200, `${report}: ${res.data?.message}`);
    }

});


test("reports: exports work for reports without a custom layout", { skip }, async () => {

    // Excel / PDF / CSV were failing for every report except Service
    // Delivery ("Unsupported report type"). The test org's plan may not
    // allow every format, so a 403 plan message is fine, a 500 is not.
    for (const report of ["budgetVsActualReport", "donorSpendingReport", "financialReport", "programReport"]) {
        for (const format of ["excel", "pdf", "csv"]) {
            const response = await fetch(`${BASE}/reports/${report}?period=annual&year=2026&format=${format}`, {
                headers: { Authorization: `Bearer ${state.financeToken}` }
            });
            assert.ok(
                response.status === 200 || response.status === 403,
                `${report} ${format}: ${response.status} ${await response.text().catch(() => "")}`
            );
        }
    }

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

    // A reason is required
    await set(revisedLines(budget, (line, year, amount) => (line.category === "Personnel" && year === 2026 ? 450000 : amount)), { reason: "" });
    assert.equal((await submit()).status, 400);

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
