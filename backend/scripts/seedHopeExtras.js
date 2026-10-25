// =====================================================
// HOPE TEST DATA - EXTRAS (local only)
// =====================================================
//
// Adds to the large Hope test set (seedHopeTestData.js)
// what it does not create, THROUGH THE API:
//
//   12 TORs in every state (draft, submitted, returned,
//      approved, approved + activity created from it)
//   8 enterprises with 48 members (some inactive), and
//      support delivered to members
//   custom fields (beneficiary, donor, enterprise) with
//      values on 60 beneficiaries
//   5 donor share links
//   budget revisions: one approved (version 2), one
//      waiting for approval
//   a voided expense, an over-budget expense approved with
//      a reason
//   completed and dropped enrollments
//   a cancelled donation
//
// Run once after seedHopeTestData.js (it refuses when Hope
// already has TORs):
//
//   node scripts/seedHopeExtras.js
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript, argument } = require("../utils/scriptConnection");


const API = process.env.API_URL || "http://localhost:5000/api/v1";
const PASSWORD = "Demo2026pass";

const failures = [];
let done = 0;

const api = async (method, path, token, body) => {
    const response = await fetch(API + path, {
        method,
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body !== undefined ? JSON.stringify(body) : undefined
    });
    let data = null;
    try { data = await response.json(); } catch { data = null; }
    if (response.status >= 300) throw new Error(`${method} ${path} -> ${response.status} ${data?.message || ""}`);
    return data?.data ?? data;
};

const attempt = async (label, fn) => {
    try {
        const result = await fn();
        done++;
        return result;
    }
    catch (error) {
        failures.push(`${label}: ${error.message}`);
        return null;
    }
};

const pad = (n) => String(n).padStart(2, "0");
const date = (month, day) => `2026-${pad(month)}-${pad(day)}`;
const id = (value) => String(value?._id || value || "");
const section = (title) => console.log(`\n== ${title}`);
const placeOf = (record) => Object.fromEntries(["region", "regionCode", "zone", "zoneCode", "woreda", "woredaCode"].map(key => [key, record?.[key] || ""]));


const main = async () => {

    if (argument("--uri-file") || argument("--db") || !/localhost|127\.0\.0\.1/.test(API)) throw new Error("Local database and local API only.");

    await connectForScript();
    if (!/localhost|127\.0\.0\.1/.test(mongoose.connection.host)) throw new Error("Local database only.");

    const db = mongoose.connection.db;
    const org = await db.collection("organizations").findOne({ email: "info@heda-demo.org" });
    if (!org) throw new Error("Hope organization not found.");
    const mine = (extra = {}) => ({ organization: org._id, isDeleted: { $ne: true }, ...extra });

    if (await db.collection("termsofreferences").countDocuments(mine())) {
        throw new Error("Hope already has TORs: the extras were added before (rebuild with seedHopeTestData.js first).");
    }

    const login = async (email) => (await api("POST", "/auth/login", null, { email, password: PASSWORD })).token;
    const admin = await login("admin@heda-demo.org");
    const data = await login("data@heda-demo.org");
    const finance = await login("finance@heda-demo.org");

    const programs = await db.collection("programs").find(mine()).toArray();
    const projects = await db.collection("projects").find(mine()).sort({ projectCode: 1 }).toArray();
    const mainIds = new Set(projects.filter(project => project.parentProject).map(project => id(project.parentProject)));
    const work = projects.filter(project => !mainIds.has(id(project._id)) && !/Phase 2$/.test(project.name));
    const activities = await db.collection("activities").find(mine()).toArray();
    const beneficiaries = await db.collection("beneficiaries").find(mine()).sort({ beneficiaryNumber: 1 }).toArray();
    const enrollments = await db.collection("enrollments").find(mine()).toArray();
    const programOf = (programId) => programs.find(program => id(program._id) === id(programId));
    const livelihoods = programs.find(program => /Livelihood/.test(program.name));
    const placeFor = (project) => placeOf(activities.find(activity => id(activity.project) === id(project._id)) || beneficiaries[0]);

    console.log(`Hope: ${programs.length} programs, ${projects.length} projects, ${beneficiaries.length} beneficiaries`);


    // ---------------- TORs (12, every state)
    section("12 TORs in every state");
    const torPlan = [
        ["Draft", "Training"], ["Draft", "Workshop"], ["Draft", "Awareness Campaign"],
        ["Submitted", "Training"], ["Submitted", "Community Dialogue"], ["Submitted", "Field Visit"],
        ["Returned", "Workshop"], ["Returned", "Training"],
        ["Approved", "Assessment"], ["Approved", "Seminar"],
        ["Activity", "Training"], ["Activity", "Workshop"]
    ];
    let tors = 0;
    let fromTor = 0;
    for (const [n, [state, activityType]] of torPlan.entries()) {
        const project = work[(n * 3) % work.length];
        const start = date(state === "Activity" || state === "Approved" ? 9 + (n % 2) : 11, 3 + n);
        const end = date(state === "Activity" || state === "Approved" ? 9 + (n % 2) : 11, 5 + n);
        const usd = n === 5;
        const ok = await attempt(`TOR ${n + 1}`, async () => {
            const tor = await api("POST", "/tors", data, {
                title: `${activityType} - ${project.name}`, project: id(project._id), activityType,
                currency: usd ? "USD" : "ETB",
                background: `Planned ${activityType.toLowerCase()} for ${project.name}.`,
                objectives: `Reach the ${project.name} participants with a ${activityType.toLowerCase()}.`,
                expectedOutputs: "Participants trained and a follow-up plan agreed.",
                methodology: "Participatory sessions, group work and demonstrations.",
                participants: "Project participants and community leaders", expectedParticipants: 20 + n * 5,
                facilitators: "Project officer and a hired trainer", logistics: "Hall, meals and transport",
                startDate: start, endDate: end, ...placeFor(project), venue: `${project.name} training hall`,
                budgetLines: usd
                    ? [{ description: "International trainer fee", unit: "day", quantity: 3, unitCost: 400 }]
                    : [
                        { description: "Hall rent", unit: "day", quantity: 3, unitCost: 4000 + n * 250 },
                        { description: "Meals and refreshments", unit: "person-day", quantity: (20 + n * 5) * 3, unitCost: 400 },
                        { description: "Participant transport", unit: "person", quantity: 20 + n * 5, unitCost: 300 }
                    ]
            });
            if (state === "Draft") return;
            await api("POST", `/tors/${tor._id}/submit`, data);
            if (state === "Submitted") return;
            if (state === "Returned") return api("POST", `/tors/${tor._id}/return`, admin, { comment: "Add the participant list and the trainer CV." });
            await api("POST", `/tors/${tor._id}/approve`, admin, { comment: "Approved." });
            if (state === "Activity") {
                await api("POST", `/tors/${tor._id}/create-activity`, admin);
                fromTor++;
            }
        });
        if (ok !== null) tors++;
    }
    console.log(`  ${tors} TORs (${fromTor} turned into activities)`);


    // ---------------- custom fields
    section("Custom fields and values");
    const fieldDefs = [
        { module: "Beneficiary", label: "Household size", key: "household_size", type: "number" },
        { module: "Beneficiary", label: "Kebele ID number", key: "kebele_id_number", type: "text" },
        { module: "Beneficiary", label: "Uses mobile money", key: "uses_mobile_money", type: "checkbox" },
        { module: "Beneficiary", label: "Main income source", key: "main_income_source", type: "select", options: [{ label: "Farming", value: "farming" }, { label: "Trade", value: "trade" }, { label: "Daily labour", value: "daily_labour" }, { label: "None", value: "none" }] },
        { module: "Donor", label: "Grant agreement reference", key: "grant_agreement_ref", type: "text" },
        { module: "Enterprise", label: "Trade license number", key: "trade_license_number", type: "text" }
    ];
    const fields = {};
    for (const def of fieldDefs) {
        const created = await attempt(`custom field ${def.key}`, () => api("POST", "/custom-fields", admin, def));
        if (created) fields[def.key] = created._id;
    }
    let filled = 0;
    for (const [n, person] of beneficiaries.slice(0, 60).entries()) {
        const values = [
            fields.household_size && { fieldId: fields.household_size, value: 3 + (n % 6) },
            fields.kebele_id_number && { fieldId: fields.kebele_id_number, value: `KID-${String(10000 + n * 37)}` },
            fields.uses_mobile_money && { fieldId: fields.uses_mobile_money, value: n % 3 === 0 },
            fields.main_income_source && { fieldId: fields.main_income_source, value: ["farming", "trade", "daily_labour", "none"][n % 4] }
        ].filter(Boolean);
        const ok = await attempt(`custom values ${person.beneficiaryNumber}`, () => api("PUT", `/beneficiaries/${person._id}`, data, { customFields: values }));
        if (ok !== null) filled++;
    }
    console.log(`  ${Object.keys(fields).length} custom fields, values on ${filled} beneficiaries`);


    // ---------------- enterprises (8) and members
    section("8 enterprises and their members");
    const lookups = async (module, category) => Object.fromEntries((await api("GET", `/lookups/module/${module}/category/${category}`, admin)).map(row => [row.value, row._id]));
    const types = await lookups("Enterprise", "EnterpriseType");
    const ownership = await lookups("Enterprise", "OwnershipType");
    const sectors = await lookups("Enterprise", "BusinessSector");
    const first = (map, ...names) => names.map(name => map[name]).find(Boolean) || Object.values(map)[0] || null;
    const enterprisePlan = [
        ["Tesfa Women Bakery Cooperative", "Cooperative", "Cooperative Ownership", "Food Processing"],
        ["Adama Handicraft Group", "Micro Enterprise", "Partnership", "Handicrafts and Artisans"],
        ["Hawassa Youth Mobile Repair", "Micro Enterprise", "Sole Proprietorship", "Services"],
        ["Bishoftu Dairy Cooperative", "Cooperative", "Cooperative Ownership", "Livestock"],
        ["Dire Dawa Tailoring Group", "Small Enterprise", "Partnership", "Textile and Garments"],
        ["Bahir Dar Urban Gardens", "Micro Enterprise", "Cooperative Ownership", "Agriculture"],
        ["Jimma Coffee Processors", "Small Enterprise", "Partnership", "Food Processing"],
        ["Mekelle Digital Services", "Micro Enterprise", "Sole Proprietorship", "Services"]
    ];
    const livelihoodPeople = beneficiaries.filter(person => enrollments.some(enrollment => id(enrollment.beneficiary) === id(person._id) && id(enrollment.program) === id(livelihoods?._id)));
    const enterprises = [];
    for (const [n, [name, type, own, sector]] of enterprisePlan.entries()) {
        const place = placeOf(livelihoodPeople[n * 6] || beneficiaries[n]);
        const created = await attempt(`enterprise ${name}`, () => api("POST", "/enterprises", data, {
            name, status: n === 7 ? "Inactive" : "Active", country: "Ethiopia", ...place,
            enterpriseType: first(types, type), ownershipType: first(ownership, own), businessSector: first(sectors, sector),
            startDate: date(2 + (n % 3), 1), phone: `0912 ${String(300000 + n * 1111).slice(0, 6)}`,
            description: `${name}: supported by the livelihoods program.`,
            ...(fields.trade_license_number ? { customFields: [{ fieldId: fields.trade_license_number, value: `TL-${2026}-${String(n + 1).padStart(4, "0")}` }] } : {})
        }));
        if (created) enterprises.push({ ...created, n });
    }
    let members = 0;
    const memberPeople = [];
    for (const enterprise of enterprises) {
        const group = livelihoodPeople.slice(enterprise.n * 6, enterprise.n * 6 + 6);
        for (const [k, person] of group.entries()) {
            const role = k === 0 ? "Manager" : k === 1 ? "Shareholder" : k === 5 ? "Employee" : "Member";
            const inactive = k === 4 && enterprise.n % 2 === 0;
            const ok = await attempt(`member ${person.beneficiaryNumber}`, () => api("POST", "/enterprise-members", data, {
                enterprise: enterprise._id, beneficiary: id(person._id), memberRole: role,
                joinedDate: date(4 + (enterprise.n % 3), 1 + k), status: inactive ? "Inactive" : "Active",
                ...(inactive ? { leftDate: date(9, 15) } : {})
            }));
            if (ok !== null) {
                members++;
                if (!inactive) memberPeople.push(person);
            }
        }
    }
    console.log(`  ${enterprises.length} enterprises, ${members} members`);

    // support for members: business start-up grants, per person
    const grantProject = work.find(project => /Small Business Start-up/.test(project.name)) || work.find(project => id(project.program) === id(livelihoods?._id));
    if (grantProject && memberPeople.length) {
        const types2 = await api("GET", "/lookups/module/ServiceDelivery/category/ServiceType", admin);
        const units = Object.fromEntries((await api("GET", "/lookups/module/ServiceDelivery/category/Unit", admin)).map(row => [row.value, row._id]));
        const cashType = types2.find(row => row.value === "Cash Assistance");
        const donation = await db.collection("donations").findOne(mine({ project: grantProject._id, currency: "ETB", status: "Received" }));
        const group = memberPeople.slice(0, 20);
        const amounts = group.map((_, k) => 5000 + (k % 4) * 2500);
        const itemId = new mongoose.Types.ObjectId().toString();
        await attempt("member start-up grants", () => api("POST", "/service-deliveries", data, {
            status: "Delivered", program: id(grantProject.program), project: id(grantProject._id), deliveryDate: date(9, 20),
            ...placeOf(group[0]), recipientType: "Individual", allocationMethod: "Individual",
            items: [{ _id: itemId, serviceCategory: id(cashType.parentLookup), serviceType: cashType._id, quantity: 1, unit: units.ETB, unitCost: amounts.reduce((sum, value) => sum + value, 0), donation: donation ? id(donation._id) : null }],
            beneficiaries: group.map((person, k) => ({ beneficiary: id(person._id), allocations: [{ serviceItem: itemId, quantity: 0, allocatedValue: amounts[k] }] }))
        }));
        console.log(`  start-up grants to ${group.length} enterprise members`);
    }


    // ---------------- donor share links (5)
    section("5 donor share links");
    const donors = await db.collection("donors").find(mine()).limit(5).toArray();
    let links = 0;
    for (const [n, donor] of donors.entries()) {
        const donation = n % 2 ? await db.collection("donations").findOne(mine({ donor: donor._id })) : null;
        const ok = await attempt(`share link ${donor.name}`, () => api("POST", "/donor-share-links", admin, {
            donor: id(donor._id), donation: donation ? id(donation._id) : null, expiresInDays: [30, 90, 180, 365, 90][n],
            label: donation ? `${donation.title} - progress` : `${donor.name} - all donations`
        }));
        if (ok !== null) links++;
    }
    console.log(`  ${links} share links`);


    // ---------------- budget revisions
    section("Budget revisions (one approved, one waiting)");
    const projectBudgets = await db.collection("budgets").find(mine({ level: "project", status: "Approved" })).sort({ budgetCode: 1 }).toArray();
    const revise = async (budget, reason, approve) => {
        await api("POST", `/budgets/${budget._id}/revision`, finance, {});
        const saved = await api("GET", `/budgets/${budget._id}`, finance);
        const lines = saved.revision.lines.map(line => ({
            _id: line._id, category: line.category, description: line.description,
            amounts: line.amounts.map(amount => ({ fiscalYear: amount.fiscalYear, amount: line.category === "Training & Workshops" && amount.fiscalYear === 2026 ? amount.amount + 40000 : amount.amount }))
        }));
        await api("PUT", `/budgets/${budget._id}/revision`, finance, { lines, reason });
        await api("POST", `/budgets/${budget._id}/revision/submit`, finance, {});
        if (approve) await api("POST", `/budgets/${budget._id}/revision/approve`, admin, { comment: "Agreed with the donor." });
    };
    if (projectBudgets[0]) await attempt("approved revision", () => revise(projectBudgets[0], "Extra refresher training requested by the donor", true));
    if (projectBudgets[1]) await attempt("waiting revision", () => revise(projectBudgets[1], "Move funds to a second training round", false));
    console.log(`  ${projectBudgets[0]?.budgetCode} revised (version 2), ${projectBudgets[1]?.budgetCode} revision waiting for approval`);


    // ---------------- expenses: voided, over budget with a reason
    section("Expenses: voided and over budget");
    const budgetFor = async (budget) => (await api("GET", `/budgets/${budget._id}`, finance)).summary.lines;
    if (projectBudgets[2]) {
        const lines = await budgetFor(projectBudgets[2]);
        const admin2026 = lines.find(line => line.category === "Administration & Overhead");
        await attempt("voided expense", async () => {
            const created = await api("POST", "/expenses", data, { budget: id(projectBudgets[2]._id), budgetLine: admin2026._id, description: "Office rent, August (entered twice)", expenseDate: date(8, 31), amount: 12000, currency: "ETB", paymentMethod: "Bank Transfer" });
            await api("POST", `/expenses/${created._id}/submit`, data);
            // only an approved expense can be voided
            await api("POST", `/expenses/${created._id}/approve`, finance, { comment: "Paid." });
            await api("POST", `/expenses/${created._id}/void`, finance, { comment: "Duplicate of the August rent payment." });
        });
        const left = (admin2026.amounts.find(amount => amount.fiscalYear === 2026)?.remaining) || 50000;
        await attempt("over-budget expense", async () => {
            const created = await api("POST", "/expenses", data, { budget: id(projectBudgets[2]._id), budgetLine: admin2026._id, description: "Generator repair (urgent)", expenseDate: date(9, 18), amount: Math.round(left + 15000), currency: "ETB", paymentMethod: "Bank Transfer" });
            await api("POST", `/expenses/${created._id}/submit`, data);
            await api("POST", `/expenses/${created._id}/approve`, finance, { allowOverBudget: true, comment: "Urgent repair; the director approved the extra 15,000." });
        });
    }
    console.log("  1 voided, 1 approved over budget with a reason");


    // ---------------- enrollments completed / dropped, a cancelled donation
    section("Enrollments completed / dropped, a cancelled donation");
    let changed = 0;
    for (const [n, enrollment] of enrollments.slice(0, 40).entries()) {
        const completed = n % 2 === 0;
        const ok = await attempt(`enrollment ${n + 1}`, () => api("PUT", `/enrollments/${enrollment._id}`, data,
            completed ? { status: "Completed", completionDate: date(9, 30) } : { status: "Dropped", remarks: "Moved out of the area." }));
        if (ok !== null) changed++;
    }
    const pledged = await db.collection("donations").findOne(mine({ status: "Pledged" }));
    if (pledged) await attempt("cancelled donation", () => api("PUT", `/donations/${pledged._id}`, admin, { status: "Cancelled", description: "The donor withdrew the pledge." }));
    console.log(`  ${changed} enrollments completed or dropped; ${pledged ? pledged.donationCode : "no"} pledge cancelled`);


    console.log(`\n== Done: ${done} records created or changed, ${failures.length} failed`);
    for (const failure of failures.slice(0, 40)) console.log(`  FAIL ${failure}`);
    process.exitCode = failures.length ? 1 : 0;

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
