// =====================================================
// DEMO DATA + END-TO-END WORKFLOW TEST
// =====================================================
//
// Builds one realistic demo organization THROUGH THE API
// (like a user clicking through the app), so every step
// is also a test of that workflow. Prints PASS / FAIL per
// step and a summary at the end.
//
//   node scripts/seedDemoData.js --reset --yes   (wipe + build)
//   node scripts/seedDemoData.js                 (build only, empty org data)
//
// --reset deletes ALL organization data in the database from
// MONGO_URI (.env). Kept: plans, locations (adminareas) and
// super admin users. Take a backup first
// (scripts/backupDatabase.js). Never run it on live.
//
// The backend must be running (API_URL, default
// http://localhost:5000/api/v1).
//
// Add the demo organization to ANOTHER database (no reset,
// existing organizations are not touched): give its API and
// its connection (used only for the temporary super admin):
//   API_URL=https://<site>/api/v1 node scripts/seedDemoData.js --uri-file .env.atlas --db ngo_system
// --reset is refused for anything but the local database.
//
// Demo logins (password for all: Demo2026pass):
//   admin@heda-demo.org     organization admin
//   data@heda-demo.org      data entry
//   finance@heda-demo.org   finance officer
//   viewer@heda-demo.org    viewer
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { hashPassword } = require("../utils/password");

const { argument, connectForScript } = require("../utils/scriptConnection");


const API = process.env.API_URL || "http://localhost:5000/api/v1";
const PASSWORD = "Demo2026pass";
const DOMAIN = "heda-demo.org";

const RESET = process.argv.includes("--reset");
const CONFIRMED = process.argv.includes("--yes");
const ENRICH_ONLY = process.argv.includes("--enrich-deliveries");

const KEEP_COLLECTIONS = ["plans", "adminareas"];

const TEMP_SUPER_ADMIN = "seed-superadmin@local.test";


// =====================================================
// RESULT LOG
// =====================================================

const results = [];

const log = (status, name, detail = "") => {
    results.push({ status, name, detail });
    const mark = status === "PASS" ? "  ok  " : status === "FAIL" ? " FAIL " : " note ";
    console.log(`[${mark}] ${name}${detail ? ` - ${detail}` : ""}`);
};

// Runs one step; a failure is recorded and the run continues
const step = async (name, fn) => {
    try {
        const value = await fn();
        log("PASS", name);
        return value;
    }
    catch (error) {
        log("FAIL", name, error.message);
        return null;
    }
};

// A check that must hold (adds a FAIL instead of throwing)
const check = (name, condition, detail = "") =>
    log(condition ? "PASS" : "FAIL", name, condition ? "" : detail);


// =====================================================
// HTTP
// =====================================================

const api = async (method, path, { token, body, expect } = {}) => {

    const response =
        await fetch(`${API}${path}`, {
            method,
            headers: {
                "Content-Type": "application/json",
                ...(token ? { Authorization: `Bearer ${token}` } : {})
            },
            body: body !== undefined ? JSON.stringify(body) : undefined
        });

    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { message: text.slice(0, 200) }; }

    const ok = expect ? response.status === expect : response.status < 300;

    if (!ok) {
        const details = Array.isArray(data?.errors) ? data.errors.map(item => item.message || item).join("; ") : "";
        throw new Error(`${method} ${path} -> ${response.status} ${data?.message || ""}${details ? ` (${details})` : ""}`);
    }

    return data;

};

const login = async (email, password = PASSWORD) =>
    (await api("POST", "/auth/login", { body: { email, password } })).data.token;

const pause = (ms) => new Promise(resolve => setTimeout(resolve, ms));


// =====================================================
// DATABASE (reset + temporary super admin only)
// =====================================================

const resetDatabase = async () => {

    const db = mongoose.connection.db;
    const collections = await db.listCollections().toArray();

    for (const { name } of collections) {
        if (KEEP_COLLECTIONS.includes(name) || name.startsWith("system.")) continue;
        if (name === "users") {
            const result = await db.collection("users").deleteMany({ role: { $ne: "super_admin" } });
            console.log(`  users: removed ${result.deletedCount} (super admins kept)`);
            continue;
        }
        const result = await db.collection(name).deleteMany({});
        console.log(`  ${name}: removed ${result.deletedCount}`);
    }

};

// The plan upgrade is done as a super admin would, through the
// API. A temporary super admin is used so nobody's real password
// is needed; it is removed at the end.
const createTempSuperAdmin = async () => {
    const users = mongoose.connection.db.collection("users");
    await users.deleteOne({ email: TEMP_SUPER_ADMIN });
    await users.insertOne({
        organization: null,
        name: "Seed Super Admin",
        email: TEMP_SUPER_ADMIN,
        password: await hashPassword("SeedSuper2026x"),
        role: "super_admin",
        status: "active",
        failedLoginAttempts: 0,
        lockUntil: null,
        createdAt: new Date(),
        updatedAt: new Date()
    });
};

const removeTempSuperAdmin = () =>
    mongoose.connection.db.collection("users").deleteOne({ email: TEMP_SUPER_ADMIN });


// =====================================================
// HELPERS FOR IDS
// =====================================================

const ids = {};

// Lookup values of a module / category: { "Female": id, ... }
const lookupMap = async (token, module, category) => {
    const response = await api("GET", `/lookups/module/${module}/category/${category}`, { token });
    const list = Array.isArray(response.data) ? response.data : response.data?.data || [];
    return Object.fromEntries(list.map(item => [item.value, item._id]));
};

const pick = (map, name) => {
    if (!map[name]) throw new Error(`lookup value "${name}" not found (have: ${Object.keys(map).slice(0, 8).join(", ")}...)`);
    return map[name];
};

const yearly = (values) =>
    Object.entries(values).map(([fiscalYear, amount]) => ({ fiscalYear: Number(fiscalYear), amount }));


const lookupList = async (token, module, category) => {
    const response = await api("GET", `/lookups/module/${module}/category/${category}`, { token });
    return Array.isArray(response.data) ? response.data : response.data?.data || [];
};

// Real region / zone / woreda from the locations list
const place = async (token, regionName, zoneIndex = 0, woredaIndex = 0) => {
    const list = async (query) => {
        const response = await api("GET", `/locations?${query}`, { token });
        return Array.isArray(response.data) ? response.data : response.data?.data || [];
    };
    const region = (await list("level=1")).find(item => item.name === regionName);
    if (!region) throw new Error(`region ${regionName} not found`);
    const zones = await list(`level=2&parent=${region.pcode}`);
    const zone = zones[Math.min(zoneIndex, zones.length - 1)];
    const woredas = await list(`level=3&parent=${zone.pcode}`);
    // Some regions (Addis Ababa) stop at the second level
    const woreda = woredas[Math.min(woredaIndex, woredas.length - 1)] || { name: "", pcode: "" };
    return {
        region: region.name, regionCode: region.pcode,
        zone: zone.name, zoneCode: zone.pcode,
        woreda: woreda.name, woredaCode: woreda.pcode
    };
};


// =====================================================
// 1. ORGANIZATION, PLAN, USERS
// =====================================================

const setupOrganization = async () => {

    console.log("\n== Organization, plan and users");

    await step("Sign-up: register the organization and its admin", () =>
        api("POST", "/organizations", {
            body: {
                name: "Hope for Ethiopia Development Association",
                email: `info@${DOMAIN}`,
                phone: "0911223344",
                country: "Ethiopia",
                admin: { name: "Selamawit Tesfaye", email: `admin@${DOMAIN}`, password: PASSWORD }
            }
        }));

    ids.admin = await step("Login as organization admin", () => login(`admin@${DOMAIN}`));
    if (!ids.admin) throw new Error("Cannot continue without the admin login.");

    // Free plan: 2 users. Upgrade as the super admin would.
    await step("Super admin: change the plan to Professional", async () => {
        await createTempSuperAdmin();
        const superToken = await login(TEMP_SUPER_ADMIN, "SeedSuper2026x");
        const plans = (await api("GET", "/plans", { token: superToken })).data;
        const list = Array.isArray(plans) ? plans : plans?.data || plans?.plans || [];
        const pro = list.find(plan => plan.code === "PRO");
        if (!pro) throw new Error("PRO plan not found");
        const organizations = (await api("GET", "/admin/organizations", { token: superToken })).data;
        const orgList = Array.isArray(organizations) ? organizations : organizations?.data || organizations?.organizations || [];
        const organization = orgList.find(item => item.email === `info@${DOMAIN}`);
        if (!organization) throw new Error("organization not found in super admin list");
        ids.organizationId = organization._id;
        await api("PUT", `/subscriptions/change/${organization._id}`, { token: superToken, body: { planId: pro._id } });
    });

    const user = (name, email, role) =>
        step(`Admin creates user: ${name} (${role})`, () =>
            api("POST", "/users", { token: ids.admin, body: { name, email, password: PASSWORD, role } }));

    await user("Mesfin Alemu", `data@${DOMAIN}`, "data_entry");
    await user("Hirut Bekele", `finance@${DOMAIN}`, "finance_officer");
    await user("Dawit Haile", `viewer@${DOMAIN}`, "viewer");

    ids.data = await step("Login as data entry", () => login(`data@${DOMAIN}`));
    ids.finance = await step("Login as finance officer", () => login(`finance@${DOMAIN}`));
    ids.viewer = await step("Login as viewer", () => login(`viewer@${DOMAIN}`));

    // Role limits
    await step("Viewer cannot create a program (403)", () =>
        api("POST", "/programs", { token: ids.viewer, body: { name: "Not allowed", startDate: "2026-01-01" }, expect: 403 }));
    await step("Data entry cannot create a budget (403)", () =>
        api("POST", "/budgets", { token: ids.data, body: { level: "program", name: "x", program: "000000000000000000000000", startYear: 2026, endYear: 2026 }, expect: 403 }));

};


// =====================================================
// 2. LOOKUPS AND LOCATIONS
// =====================================================

const setupLookups = async () => {

    console.log("\n== Lookups and locations (seeded at sign-up)");

    ids.gender = await step("Lookups: genders", () => lookupMap(ids.admin, "Beneficiary", "Gender"));
    ids.education = await step("Lookups: education levels", () => lookupMap(ids.admin, "Beneficiary", "EducationLevel"));
    ids.occupation = await step("Lookups: occupations", () => lookupMap(ids.admin, "Beneficiary", "Occupation"));
    ids.disability = await step("Lookups: disability types", () => lookupMap(ids.admin, "Beneficiary", "DisabilityType"));
    ids.marital = await step("Lookups: marital status", () => lookupMap(ids.admin, "Beneficiary", "MaritalStatus"));
    ids.enterpriseType = await step("Lookups: enterprise types", () => lookupMap(ids.admin, "Enterprise", "EnterpriseType"));
    ids.ownership = await step("Lookups: ownership types", () => lookupMap(ids.admin, "Enterprise", "OwnershipType"));
    ids.sector = await step("Lookups: business sectors", () => lookupMap(ids.admin, "Enterprise", "BusinessSector"));
    ids.serviceCategories = await step("Lookups: service categories", () => lookupList(ids.admin, "ServiceDelivery", "ServiceCategory"));
    ids.serviceTypes = await step("Lookups: service types", () => lookupList(ids.admin, "ServiceDelivery", "ServiceType"));
    ids.units = await step("Lookups: units", () => lookupMap(ids.admin, "ServiceDelivery", "Unit"));

    console.log(`  genders: ${Object.keys(ids.gender || {}).join(", ")}`);
    console.log(`  education: ${Object.keys(ids.education || {}).join(", ")}`);
    console.log(`  occupation: ${Object.keys(ids.occupation || {}).join(", ")}`);
    console.log(`  marital: ${Object.keys(ids.marital || {}).join(", ")}`);
    console.log(`  enterprise types: ${Object.keys(ids.enterpriseType || {}).join(", ")}`);
    console.log(`  ownership: ${Object.keys(ids.ownership || {}).join(", ")}`);
    console.log(`  sectors: ${Object.keys(ids.sector || {}).slice(0, 12).join(", ")}`);
    console.log(`  service categories: ${(ids.serviceCategories || []).map(item => item.value).join(", ")}`);
    console.log(`  service types: ${(ids.serviceTypes || []).map(item => item.value).join(", ")}`);
    console.log(`  units: ${Object.keys(ids.units || {}).join(", ")}`);

    ids.places = {};
    ids.places.amhara = await step("Locations: Amhara zone / woreda", () => place(ids.admin, "Amhara", 0, 0));
    ids.places.amhara2 = await step("Locations: second Amhara woreda", () => place(ids.admin, "Amhara", 0, 1));
    ids.places.oromia = await step("Locations: Oromia zone / woreda", () => place(ids.admin, "Oromia", 1, 0));
    ids.places.afar = await step("Locations: Afar zone / woreda", () => place(ids.admin, "Afar", 0, 0));
    ids.places.addis = await step("Locations: Addis Ababa sub city", () => place(ids.admin, "Addis Ababa", 0, 0));

};


// =====================================================
// 3. PROGRAMS, PROJECTS, DONORS, DONATIONS
// =====================================================

const PROGRAMS = [
    {
        key: "edu", name: "Education Quality Improvement", category: "Education", targetBeneficiaries: 3000,
        description: "Improve learning outcomes in rural primary schools through teacher training, learning materials and school feeding.",
        projects: [
            { key: "teachers", name: "Teacher Professional Development", donor: "gef", description: "In-service training for primary school teachers in North Shewa." },
            { key: "materials", name: "Learning Materials and School Feeding", donor: "act", description: "Textbooks, exercise books and daily meals for children in need." }
        ]
    },
    {
        key: "women", name: "Women and Girls Economic Empowerment", category: "Livelihoods", targetBeneficiaries: 1500,
        description: "Strengthen the income, savings and leadership of women and girls through skills training and small enterprises.",
        projects: [
            { key: "savings", name: "Women Savings and Credit Groups", donor: "wef", description: "Village savings groups, financial literacy and seed grants." },
            { key: "girls", name: "Adolescent Girls Life Skills", donor: "wef", description: "Life-skills clubs, menstrual hygiene support and mentoring." }
        ]
    },
    {
        key: "wash", name: "WASH and Climate Resilience", category: "WASH", targetBeneficiaries: 5000,
        description: "Safe water, sanitation and drought preparedness for pastoral communities.",
        projects: [
            { key: "water", name: "Community Water Points", donor: "gef", description: "Rehabilitation of water points and water committee training." }
        ]
    }
];

const DONORS = [
    { key: "gef", name: "Global Education Fund", donorType: "Foundation", country: "United Kingdom", email: "grants@gef-demo.org", contactPerson: "Sarah Collins", phone: "+44 20 7946 0000" },
    { key: "wef", name: "Womens Empowerment Foundation", donorType: "NGO", country: "Netherlands", email: "partners@wef-demo.org", contactPerson: "Anneke de Vries", phone: "+31 20 555 0101" },
    { key: "act", name: "Addis Community Trust", donorType: "Organization", country: "Ethiopia", email: "info@act-demo.org", contactPerson: "Yonas Girma", phone: "0116 620 000" },
    { key: "abebe", name: "Abebe Kebede", donorType: "Individual", country: "Ethiopia", email: "abebe.kebede@example.com", contactPerson: "Abebe Kebede", phone: "0911 000 111" }
];

const setupProgramsAndDonors = async () => {

    console.log("\n== Donors, programs, projects, donations");

    ids.donors = {};
    for (const donor of DONORS) {
        const { key, ...body } = donor;
        const created = await step(`Donor: ${donor.name}`, () =>
            api("POST", "/donors", { token: ids.admin, body: { ...body, status: "Active", donorSince: "2024-01-15" } }));
        if (created) ids.donors[key] = created.data._id;
    }

    ids.programs = {};
    ids.projects = {};
    for (const program of PROGRAMS) {
        const created = await step(`Program: ${program.name}`, () =>
            api("POST", "/programs", {
                token: ids.admin,
                body: {
                    name: program.name, category: program.category, description: program.description,
                    targetBeneficiaries: program.targetBeneficiaries,
                    startDate: "2026-01-01", endDate: "2028-12-31", status: "Active"
                }
            }));
        if (!created) continue;
        ids.programs[program.key] = created.data._id;

        for (const project of program.projects) {
            const createdProject = await step(`Project: ${project.name}`, () =>
                api("POST", "/projects", {
                    token: ids.admin,
                    body: {
                        program: ids.programs[program.key], name: project.name, description: project.description,
                        donor: ids.donors[project.donor] || null,
                        startDate: "2026-01-01", endDate: "2028-12-31", status: "Active"
                    }
                }));
            if (createdProject) ids.projects[project.key] = createdProject.data._id;
        }
    }

    const donation = (title, donor, project, amount, currency, date, extra = {}) =>
        step(`Donation: ${title}`, async () => {
            const created = await api("POST", "/donations", {
                token: ids.admin,
                body: {
                    title, donor: ids.donors[donor], project: ids.projects[project] || null,
                    amount, currency, donationDate: date,
                    fundingSource: extra.fundingSource || "Grant",
                    fundingRestriction: extra.restriction || "Restricted",
                    donationType: extra.donationType || "Bank Transfer",
                    status: extra.status || "Received",
                    receiptNumber: extra.receipt || null,
                    description: extra.description || null
                }
            });
            return created.data._id;
        });

    ids.donations = {};
    ids.donations.teachers = await donation("Teacher Training Grant 2026", "gef", "teachers", 2400000, "ETB", "2026-01-20", { receipt: "RC-2026-001" });
    ids.donations.water = await donation("Water Points Grant 2026", "gef", "water", 3200000, "ETB", "2026-02-10", { receipt: "RC-2026-002" });
    ids.donations.savings = await donation("Savings Groups Grant", "wef", "savings", 1800000, "ETB", "2026-01-25", { receipt: "RC-2026-003" });
    ids.donations.girls = await donation("Girls Life Skills Grant", "wef", "girls", 15000, "EUR", "2026-03-01", { receipt: "RC-2026-004" });
    ids.donations.materials = await donation("School Feeding Support", "act", "materials", 900000, "ETB", "2026-02-15", { receipt: "RC-2026-005" });
    ids.donations.pledge = await donation("Exercise Books Pledge", "abebe", "materials", 50000, "ETB", "2026-09-01", { status: "Pledged", fundingSource: "Donation", restriction: "Unrestricted", donationType: "Cash" });

};


// =====================================================
// 4. BUDGETS (program ceilings, project lines, approval)
// =====================================================

const line = (category, description, amounts) => ({ category, description, amounts: yearly(amounts) });

const setupBudgets = async () => {

    console.log("\n== Budgets (finance officer)");

    ids.budgets = {};
    const fin = ids.finance;

    const programBudget = async (key, name, amounts) => {
        const created = await step(`Program budget: ${name}`, () =>
            api("POST", "/budgets", {
                token: fin,
                body: { level: "program", name, program: ids.programs[key], currency: "ETB", startYear: 2026, endYear: 2028, yearlyAmounts: yearly(amounts) }
            }));
        if (!created) return;
        ids.budgets[key] = created.data._id;
        await step(`Submit + approve program budget: ${name}`, async () => {
            await api("POST", `/budgets/${created.data._id}/submit`, { token: fin });
            await api("POST", `/budgets/${created.data._id}/approve`, { token: ids.admin, body: { comment: "Approved by the board, FY 2026 plan." } });
        });
    };

    await programBudget("edu", "Education Program Budget 2026-2028", { 2026: 3000000, 2027: 3200000, 2028: 3000000 });
    await programBudget("women", "Women and Girls Program Budget 2026-2028", { 2026: 2000000, 2027: 2200000, 2028: 2000000 });
    await programBudget("wash", "WASH Program Budget 2026-2028", { 2026: 3500000, 2027: 3000000, 2028: 2500000 });

    const projectBudget = async (key, name, endYear, lines) => {
        const created = await step(`Project budget: ${name}`, () =>
            api("POST", "/budgets", {
                token: fin,
                body: { level: "project", name, project: ids.projects[key], currency: "ETB", startYear: 2026, endYear, lines }
            }));
        if (created) ids.budgets[key] = created.data._id;
        return created?.data;
    };

    const approve = (key, label) =>
        step(`Submit + approve: ${label}`, async () => {
            await api("POST", `/budgets/${ids.budgets[key]}/submit`, { token: fin });
            await api("POST", `/budgets/${ids.budgets[key]}/approve`, { token: ids.admin, body: { comment: "Within the program ceiling." } });
        });

    await projectBudget("teachers", "Teacher Development Budget 2026-2027", 2027, [
        line("Personnel", "Two master trainers", { 2026: 600000, 2027: 600000 }),
        line("Training & Workshops", "Cluster workshops for 240 teachers", { 2026: 900000, 2027: 800000 }),
        line("Travel & Per Diem", "Per diem and transport for participants", { 2026: 250000, 2027: 250000 }),
        line("Supplies & Materials", "Training manuals and stationery", { 2026: 120000, 2027: 100000 }),
        line("Administration & Overhead", "Office running costs (7%)", { 2026: 130000, 2027: 120000 })
    ]);
    await approve("teachers", "Teacher Development Budget");

    await projectBudget("materials", "Learning Materials and Feeding Budget 2026-2027", 2027, [
        line("Direct Beneficiary Support", "School meals for 600 children", { 2026: 600000, 2027: 650000 }),
        line("Supplies & Materials", "Exercise books, textbooks and pens", { 2026: 250000, 2027: 250000 }),
        line("Administration & Overhead", "Office running costs", { 2026: 50000, 2027: 50000 })
    ]);
    await approve("materials", "Learning Materials Budget");

    await projectBudget("savings", "Savings Groups Budget 2026-2028", 2028, [
        line("Personnel", "Community facilitators", { 2026: 300000, 2027: 320000, 2028: 320000 }),
        line("Training & Workshops", "Financial literacy and business skills", { 2026: 400000, 2027: 400000, 2028: 350000 }),
        line("Direct Beneficiary Support", "Seed grants to savings groups", { 2026: 500000, 2027: 600000, 2028: 500000 }),
        line("Travel & Per Diem", "Field monitoring", { 2026: 100000, 2027: 100000, 2028: 100000 }),
        line("Administration & Overhead", "Office running costs", { 2026: 100000, 2027: 100000, 2028: 100000 })
    ]);
    await approve("savings", "Savings Groups Budget");

    await projectBudget("water", "Community Water Points Budget 2026-2028", 2028, [
        line("Equipment", "Solar pumps and pipes", { 2026: 1500000, 2027: 1000000, 2028: 800000 }),
        line("Consultancy & Services", "Hydro-geological survey and design", { 2026: 400000, 2027: 200000, 2028: 100000 }),
        line("Training & Workshops", "Water committee training", { 2026: 300000, 2027: 300000, 2028: 300000 }),
        line("Travel & Per Diem", "Site supervision", { 2026: 150000, 2027: 150000, 2028: 150000 }),
        line("Administration & Overhead", "Office running costs", { 2026: 150000, 2027: 150000, 2028: 150000 })
    ]);
    await approve("water", "Community Water Points Budget");

    // Over the program ceiling: refused on submit
    await projectBudget("girls", "Girls Life Skills Budget 2026-2027", 2027, [
        line("Training & Workshops", "Life-skills clubs in 10 schools", { 2026: 450000, 2027: 400000 }),
        line("Supplies & Materials", "Menstrual hygiene kits", { 2026: 200000, 2027: 200000 }),
        line("Personnel", "Mentors", { 2026: 100000, 2027: 100000 })
    ]);
    await step("Budget over the program ceiling is refused on submit (400)", () =>
        api("POST", `/budgets/${ids.budgets.girls}/submit`, { token: fin, expect: 400 }));

    await step("Finance fixes the girls budget and submits it", async () => {
        await api("PUT", `/budgets/${ids.budgets.girls}`, {
            token: fin,
            body: {
                lines: [
                    line("Training & Workshops", "Life-skills clubs in 10 schools", { 2026: 250000, 2027: 300000 }),
                    line("Supplies & Materials", "Menstrual hygiene kits", { 2026: 200000, 2027: 200000 }),
                    line("Personnel", "Mentors", { 2026: 100000, 2027: 100000 })
                ]
            }
        });
        await api("POST", `/budgets/${ids.budgets.girls}/submit`, { token: fin });
    });
    await step("Admin returns the girls budget with a comment", () =>
        api("POST", `/budgets/${ids.budgets.girls}/return`, { token: ids.admin, body: { comment: "Please split the hygiene kits per school before approval." } }));
    await step("Finance edits and resubmits (left Submitted for the demo)", async () => {
        await api("PUT", `/budgets/${ids.budgets.girls}`, { token: fin, body: { description: "Hygiene kits: 20 per school, 10 schools." } });
        await api("POST", `/budgets/${ids.budgets.girls}/submit`, { token: fin });
    });

    const water = (await api("GET", `/budgets/${ids.budgets.water}`, { token: fin })).data;
    check("Approved budgets are locked (edit refused)", (await api("PUT", `/budgets/${ids.budgets.water}`, { token: fin, body: { name: "x y z" } }).then(() => false).catch(error => /409/.test(error.message))));
    check("Program budget shows allocation to projects",
        (await api("GET", `/budgets/${ids.budgets.wash}`, { token: fin })).data.summary.allocation.totalAllocated === water.totalAmount,
        "allocated total differs from the water project budget");

};


// =====================================================
// 5. TORS, ACTIVITIES, ACTIVITY RUNS
// =====================================================

const setupActivities = async () => {

    console.log("\n== TORs, activities, activity runs");

    ids.activities = {};
    ids.runs = {};
    const am = ids.places.amhara || {};
    const om = ids.places.oromia || {};
    const af = ids.places.afar || {};

    const tor = (key, title, project, body) =>
        step(`TOR: ${title}`, async () => {
            const created = await api("POST", "/tors", {
                token: ids.data,
                body: { title, project: ids.projects[project], currency: "ETB", ...body }
            });
            ids[`tor_${key}`] = created.data._id;
            return created.data._id;
        });

    // 1) Teacher training: submitted, approved, activity created from it
    await tor("teachers", "Cluster Teacher Training on Active Learning", "teachers", {
        activityType: "Training",
        background: "Teachers in rural North Shewa schools have had little in-service training on active learning methods.",
        objectives: "Train 40 grade 1-4 teachers on active learning, continuous assessment and classroom management.",
        expectedOutputs: "40 teachers trained; lesson plans revised; follow-up visits planned.",
        methodology: "Three days of participatory sessions, demonstrations and peer teaching.",
        participants: "Grade 1-4 teachers from 10 schools", expectedParticipants: 40,
        facilitators: "Two master trainers", logistics: "Hall, lunch and refreshments for 3 days",
        startDate: "2026-04-14", endDate: "2026-04-16", ...am, venue: "Debre Berhan Teachers College",
        budgetLines: [
            { description: "Hall rent", unit: "day", quantity: 3, unitCost: 5000 },
            { description: "Lunch and refreshments", unit: "person-day", quantity: 120, unitCost: 450 },
            { description: "Participant per diem", unit: "person-day", quantity: 120, unitCost: 600 },
            { description: "Training manuals", unit: "copy", quantity: 45, unitCost: 350 }
        ]
    });
    await step("TOR submitted and approved; activity created from it", async () => {
        await api("POST", `/tors/${ids.tor_teachers}/submit`, { token: ids.data });
        await api("POST", `/tors/${ids.tor_teachers}/approve`, { token: ids.admin, body: { comment: "Good plan." } });
        const result = await api("POST", `/tors/${ids.tor_teachers}/create-activity`, { token: ids.admin });
        ids.activities.teachers = result.data?.activity?._id || result.data?._id || result.data?.activity;
        if (!ids.activities.teachers) throw new Error(`no activity id in response: ${JSON.stringify(result.data).slice(0, 200)}`);
    });

    // 2) Savings group training: approved, created from TOR
    await tor("savings", "Financial Literacy Training for Savings Groups", "savings", {
        activityType: "Training",
        background: "Most savings groups formed in 2025 keep records poorly and lose track of loans.",
        objectives: "Train savings group leaders on bookkeeping, savings and loan management.",
        expectedOutputs: "30 group leaders able to keep a savings and loan register.",
        expectedParticipants: 30, startDate: "2026-05-05", endDate: "2026-05-07", ...om, venue: "Adama Youth Center",
        budgetLines: [
            { description: "Trainer fee", unit: "day", quantity: 3, unitCost: 4000 },
            { description: "Meals", unit: "person-day", quantity: 90, unitCost: 400 }
        ]
    });
    await step("Savings TOR approved; activity created", async () => {
        await api("POST", `/tors/${ids.tor_savings}/submit`, { token: ids.data });
        await api("POST", `/tors/${ids.tor_savings}/approve`, { token: ids.admin, body: {} });
        const result = await api("POST", `/tors/${ids.tor_savings}/create-activity`, { token: ids.admin });
        ids.activities.savings = result.data?.activity?._id || result.data?._id || result.data?.activity;
    });

    // 3) Water committee TOR: returned for changes (stays Returned)
    await tor("water", "Water Committee Training", "water", {
        activityType: "Workshop",
        background: "Several rehabilitated water points broke down within months because committees lack maintenance skills.",
        objectives: "Train water committees on operation and maintenance.",
        expectedOutputs: "25 committee members trained; maintenance plan per water point.",
        expectedParticipants: 25, startDate: "2026-11-10", endDate: "2026-11-11", ...af,
        budgetLines: [{ description: "Workshop costs", unit: "lump sum", quantity: 1, unitCost: 60000 }]
    });
    await step("Water TOR submitted and returned with a comment", async () => {
        await api("POST", `/tors/${ids.tor_water}/submit`, { token: ids.data });
        await api("POST", `/tors/${ids.tor_water}/return`, { token: ids.admin, body: { comment: "Add the list of water points and the trainer CVs." } });
    });

    // 4) Draft TOR
    await tor("girls", "Girls Club Mentor Orientation", "girls", {
        activityType: "Workshop", objectives: "Orient mentors on the girls club curriculum.", expectedParticipants: 20,
        startDate: "2026-12-02", endDate: "2026-12-02", ...am
    });

    // Activities created directly
    const activity = (key, project, name, body) =>
        step(`Activity: ${name}`, async () => {
            // Data entry may only create activities from an approved TOR
            const created = await api("POST", "/activities", {
                token: ids.admin,
                body: { project: ids.projects[project], name, ...body }
            });
            ids.activities[key] = created.data._id;
        });

    await activity("feeding", "materials", "School Feeding Distribution", {
        activityType: "Distribution", participantSource: "Enrolled Beneficiaries", targetGroups: ["Children", "Students"],
        activityDate: "2026-02-20", ...am, location: "Debre Berhan primary schools", targetParticipants: 600, status: "Ongoing"
    });
    await activity("water", "water", "Water Point Rehabilitation", {
        activityType: "Field Visit", participantSource: "Mixed", targetGroups: ["Farmers", "Community Leaders"],
        activityDate: "2026-03-10", ...af, targetParticipants: 500, status: "Ongoing"
    });
    await activity("girls", "girls", "Girls Life-Skills Clubs", {
        activityType: "Training", participantSource: "Enrolled Beneficiaries", targetGroups: ["Youth", "Women"],
        activityDate: "2026-03-01", ...am, targetParticipants: 200, status: "Ongoing"
    });

    // Activity runs (batches)
    const run = (key, activityKey, name, body) =>
        step(`Activity run: ${name}`, async () => {
            if (!ids.activities[activityKey]) throw new Error("activity missing");
            const created = await api("POST", "/activity-runs", {
                token: ids.data,
                body: { activity: ids.activities[activityKey], name, ...body }
            });
            ids.runs[key] = created.data._id;
        });

    await run("teachers1", "teachers", "Batch 1 - Debre Berhan cluster", { startDate: "2026-04-14", endDate: "2026-04-16", ...am, location: "Debre Berhan Teachers College", status: "Completed" });
    await run("teachers2", "teachers", "Batch 2 - Ankober cluster", { startDate: "2026-11-17", endDate: "2026-11-19", ...(ids.places.amhara2 || am), status: "Planned" });
    await run("savings1", "savings", "Adama savings group leaders", { startDate: "2026-05-05", endDate: "2026-05-07", ...om, location: "Adama Youth Center", status: "Completed" });
    await run("feeding1", "feeding", "Term 1 feeding", { startDate: "2026-02-20", endDate: "2026-06-30", ...am, status: "Completed" });
    await run("feeding2", "feeding", "Term 2 feeding", { startDate: "2026-09-15", endDate: "2027-01-30", ...am, status: "Active" });
    await run("girls1", "girls", "Girls clubs - first cohort", { startDate: "2026-03-01", endDate: "2026-12-15", ...am, status: "Active" });
    await run("water1", "water", "Afar water points phase 1", { startDate: "2026-03-10", endDate: "2026-09-30", ...af, status: "Completed" });

};


// =====================================================
// 6. BENEFICIARIES, ENROLLMENTS, ATTENDANCE
// =====================================================

const FEMALE = ["Almaz", "Tigist", "Meseret", "Hana", "Selam", "Bethlehem", "Mekdes", "Tsehay", "Aster", "Genet", "Hiwot", "Rahel", "Kidist", "Yeshi", "Zenebech", "Lemlem", "Birtukan", "Saba", "Eden", "Martha"];
const MALE = ["Abebe", "Bekele", "Dawit", "Getachew", "Haile", "Kebede", "Mulugeta", "Solomon", "Tesfaye", "Yonas", "Girma", "Tadesse", "Alemayehu", "Fikadu", "Berhanu", "Henok"];
const FATHERS = ["Alemu", "Bekele", "Demissie", "Gebre", "Hailu", "Kassa", "Mekonnen", "Negash", "Tefera", "Wolde", "Ayele", "Desta", "Assefa", "Worku"];
const GRANDFATHERS = ["Abera", "Bayu", "Chala", "Derese", "Endale", "Fanta", "Gutema", "Jemal", "Lema", "Mamo", "Regassa", "Shiferaw"];

const setupBeneficiaries = async () => {

    console.log("\n== Beneficiaries, enrollments, attendance");

    ids.beneficiaries = [];

    const plan = [];
    // Teachers (adults, Amhara), children (Amhara), women (Oromia), girls (Amhara), pastoralists (Afar)
    for (let i = 0; i < 12; i++) plan.push({ group: "teachers", female: i % 2 === 0, age: 26 + (i * 3) % 20, place: ids.places.amhara, occupation: "Government Employee", education: "Diploma" });
    for (let i = 0; i < 14; i++) plan.push({ group: "children", female: i % 2 === 1, age: 8 + (i % 6), place: ids.places.amhara, occupation: "Student", education: "Primary Education" });
    for (let i = 0; i < 14; i++) plan.push({ group: "women", female: true, age: 24 + (i * 2) % 26, place: ids.places.oromia, occupation: i % 3 === 0 ? "Trader" : "Household Work", education: i % 4 === 0 ? "No Formal Education" : "Primary Education" });
    for (let i = 0; i < 10; i++) plan.push({ group: "girls", female: true, age: 13 + (i % 5), place: ids.places.amhara, occupation: "Student", education: "Secondary Education" });
    for (let i = 0; i < 8; i++) plan.push({ group: "water", female: i % 3 === 0, age: 30 + i * 4, place: ids.places.afar, occupation: "Farmer", education: "No Formal Education", isPWD: i === 5 });

    let f = 0;
    let m = 0;
    for (let index = 0; index < plan.length; index++) {
        const person = plan[index];
        const firstName = person.female ? FEMALE[f++ % FEMALE.length] : MALE[m++ % MALE.length];
        let middleName = FATHERS[index % FATHERS.length];
        if (middleName === firstName) middleName = FATHERS[(index + 1) % FATHERS.length];
        const lastName = GRANDFATHERS[(index * 7) % GRANDFATHERS.length];
        const birthYear = 2026 - person.age;
        const created = await step(`Beneficiary ${index + 1}: ${firstName} ${middleName} (${person.group})`, () =>
            api("POST", "/beneficiaries", {
                token: ids.data,
                body: {
                    firstName, middleName, lastName,
                    gender: pick(ids.gender, person.female ? "Female" : "Male"),
                    dateOfBirth: `${birthYear}-0${1 + (index % 9)}-1${index % 9}`,
                    phone: person.age >= 18 ? `09${String(11000000 + index * 7919).slice(0, 8)}` : "",
                    country: "Ethiopia",
                    ...(person.place || {}),
                    kebele: `Kebele 0${1 + (index % 6)}`,
                    educationLevel: pick(ids.education, person.education),
                    occupation: pick(ids.occupation, person.occupation),
                    maritalStatus: person.age >= 22 ? pick(ids.marital, index % 4 === 0 ? "Single" : "Married") : pick(ids.marital, "Single"),
                    isPWD: Boolean(person.isPWD),
                    disabilityType: person.isPWD ? Object.values(ids.disability || {})[0] || null : null,
                    status: "Active"
                }
            }));
        if (created) {
            ids.beneficiaries.push({ ...person, id: created.data._id, name: `${firstName} ${middleName}` });
        }
    }

    await step("Duplicate beneficiary check (same name, phone) is handled", async () => {
        const first = ids.beneficiaries.find(item => item.group === "women");
        const original = (await api("GET", `/beneficiaries/${first.id}`, { token: ids.data })).data;
        const response = await fetch(`${API}/beneficiaries`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${ids.data}` },
            body: JSON.stringify({
                firstName: original.firstName, middleName: original.middleName, lastName: original.lastName,
                gender: original.gender?._id || original.gender, phone: original.phone, dateOfBirth: original.dateOfBirth
            })
        });
        if (response.status < 300) {
            const body = await response.json();
            await api("DELETE", `/beneficiaries/${body.data._id}`, { token: ids.admin });
            throw new Error("a duplicate beneficiary (same name, phone, birth date) was accepted");
        }
    });

    // Enrollments into programs
    const programOf = { teachers: "edu", children: "edu", women: "women", girls: "women", water: "wash" };
    ids.enrollments = {};
    let enrolled = 0;
    for (const person of ids.beneficiaries) {
        const created = await api("POST", "/enrollments", {
            token: ids.data,
            body: { program: ids.programs[programOf[person.group]], beneficiary: person.id, enrollmentDate: "2026-02-01", status: "Active" }
        }).catch(error => { log("FAIL", `Enroll ${person.name}`, error.message); return null; });
        if (created) {
            ids.enrollments[person.id] = created.data._id;
            enrolled++;
        }
    }
    check(`Enrollments created (${enrolled}/${ids.beneficiaries.length})`, enrolled === ids.beneficiaries.length);

    await step("Enrolling the same beneficiary twice is refused", () =>
        api("POST", "/enrollments", {
            token: ids.data,
            body: { program: ids.programs.edu, beneficiary: ids.beneficiaries[0].id, enrollmentDate: "2026-02-01" }
        }).then(() => { throw new Error("second enrollment accepted"); }, error => { if (!/40\d/.test(error.message)) throw error; }));

    // Attendance sessions + records
    const ageGroup = (age) => (age < 15 ? "Child" : age < 30 ? "Youth" : age < 60 ? "Adult" : "Elderly");
    const session = async (runKey, title, number, date, group, absent = []) => {
        const created = await step(`Attendance: ${title}`, async () => {
            const attendance = await api("POST", "/attendance", {
                token: ids.data,
                body: { activityRun: ids.runs[runKey], sessionTitle: title, sessionNumber: number, sessionDate: date, notes: "" }
            });
            const people = ids.beneficiaries.filter(item => item.group === group);
            await api("POST", `/attendance/${attendance.data._id}/records`, {
                token: ids.data,
                body: {
                    records: people.map((person, index) => ({
                        participantType: "Beneficiary",
                        beneficiary: person.id,
                        gender: person.female ? "Female" : "Male",
                        ageGroup: ageGroup(person.age),
                        disabilityStatus: Boolean(person.isPWD),
                        status: absent.includes(index) ? "Absent" : "Present"
                    }))
                }
            });
            return attendance.data._id;
        });
        return created;
    };

    await session("teachers1", "Day 1 - Active learning methods", 1, "2026-04-14", "teachers");
    await session("teachers1", "Day 2 - Continuous assessment", 2, "2026-04-15", "teachers", [3]);
    await session("teachers1", "Day 3 - Classroom management", 3, "2026-04-16", "teachers", [3, 7]);
    await session("savings1", "Bookkeeping basics", 1, "2026-05-05", "women");
    await session("savings1", "Loans and repayment", 2, "2026-05-06", "women", [2]);
    await session("girls1", "Club session - self esteem", 1, "2026-03-07", "girls");

};


// =====================================================
// 7. SERVICE DELIVERIES
// =====================================================

const serviceItem = (typeName, unitName, quantity, unitCost, donorKey, donationKey) => {
    const type = (ids.serviceTypes || []).find(item => item.value === typeName);
    if (!type) throw new Error(`service type ${typeName} not found`);
    const category = type.parentLookup?._id || type.parentLookup;
    return {
        serviceCategory: String(category),
        serviceType: type._id,
        quantity,
        unit: pick(ids.units, unitName),
        unitCost,
        donor: donorKey ? ids.donors[donorKey] : null,
        donation: donationKey ? ids.donations[donationKey] : null
    };
};

const peopleIn = (group, count) =>
    ids.beneficiaries.filter(item => item.group === group).slice(0, count).map(item => item.id);

const setupServiceDeliveries = async () => {

    console.log("\n== Service deliveries");

    ids.deliveries = {};

    const delivery = (key, label, body) =>
        step(`Service delivery: ${label}`, async () => {
            const created = await api("POST", "/service-deliveries", { token: ids.data, body: { status: "Delivered", ...body } });
            ids.deliveries[key] = created.data._id;
        });

    const am = ids.places.amhara || {};
    const om = ids.places.oromia || {};
    const af = ids.places.afar || {};

    await delivery("supplies", "School supplies to 14 children", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("children", 14),
        program: ids.programs.edu, project: ids.projects.materials, activity: ids.activities.feeding, activityRun: ids.runs.feeding1,
        items: [serviceItem("School Supplies", "Set", 14, 350, "act", "materials"), serviceItem("School Uniform", "Piece", 14, 600, "act", "materials")],
        deliveryDate: "2026-02-25", ...am, deliveryLocation: "Debre Berhan Primary School No. 1"
    });

    await delivery("meals", "School meals (institution, unallocated)", {
        recipientType: "Institution", recipientName: "Debre Berhan Primary School No. 1", allocationMethod: "Unallocated",
        program: ids.programs.edu, project: ids.projects.materials, activity: ids.activities.feeding, activityRun: ids.runs.feeding1,
        items: [serviceItem("Food Assistance", "Kg", 1200, 85, "act", "materials")],
        deliveryDate: "2026-03-20", ...am, deliveryLocation: "School kitchen"
    });

    await delivery("teachers", "Teacher support kits to 12 teachers", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("teachers", 12),
        program: ids.programs.edu, project: ids.projects.teachers, activity: ids.activities.teachers, activityRun: ids.runs.teachers1,
        items: [serviceItem("Teacher Support", "Set", 12, 900, "gef", "teachers")],
        deliveryDate: "2026-04-16", ...am
    });

    await delivery("grants", "Seed grants to 8 women", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("women", 8),
        program: ids.programs.women, project: ids.projects.savings, activity: ids.activities.savings, activityRun: ids.runs.savings1,
        items: [serviceItem("Cash Assistance", "ETB", 8, 5000, "wef", "savings")],
        deliveryDate: "2026-05-20", ...om
    });

    await delivery("training", "Business skills training for 14 women", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("women", 14),
        program: ids.programs.women, project: ids.projects.savings, activity: ids.activities.savings, activityRun: ids.runs.savings1,
        items: [serviceItem("Business Skills Training", "Session", 3, 4000, "wef", "savings")],
        deliveryDate: "2026-05-07", ...om
    });

    await delivery("hygiene", "Hygiene kits to 10 girls", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("girls", 10),
        program: ids.programs.women, project: ids.projects.girls, activity: ids.activities.girls, activityRun: ids.runs.girls1,
        items: [serviceItem("Hygiene Kit", "Set", 10, 750, "wef", "girls")],
        deliveryDate: "2026-04-05", ...am
    });

    await delivery("wash", "WASH supplies to the Afar water committee", {
        recipientType: "Group / Community", recipientName: "Afar water committee, phase 1", allocationMethod: "Group",
        beneficiaries: peopleIn("water", 7),
        program: ids.programs.wash, project: ids.projects.water, activity: ids.activities.water, activityRun: ids.runs.water1,
        items: [serviceItem("WASH Supplies", "Box", 7, 2500, "gef", "water")],
        deliveryDate: "2026-06-12", ...af
    });

    await delivery("cancelled", "Cancelled delivery (kept for audit)", {
        recipientType: "Individual", allocationMethod: "Shared", beneficiaries: peopleIn("children", 3),
        program: ids.programs.edu, project: ids.projects.materials,
        items: [serviceItem("School Fees", "ETB", 3, 400, "act", "materials")],
        deliveryDate: "2026-07-01", ...am, status: "Cancelled"
    });

    await step("Cancelled delivery is locked against edits", () =>
        api("PUT", `/service-deliveries/${ids.deliveries.cancelled}`, { token: ids.data, body: { deliveryLocation: "changed" } })
            .then(() => { throw new Error("edit of a cancelled delivery was accepted"); }, error => { if (!/40\d/.test(error.message)) throw error; }));

};


// =====================================================
// 7b. DETAIL ITEMS AND ALLOCATIONS
// =====================================================
// Adds a breakdown (detail items) and per-beneficiary
// allocations to some deliveries, through the update API.
// Also runs on its own for demo data that already exists:
//   node scripts/seedDemoData.js --enrich-deliveries [--uri-file ... --db ...]

const DELIVERY_ENRICHMENT = {

    // School supplies + uniforms to 14 children
    "SD-000001": {
        details: {
            0: [
                { name: "Exercise books", quantity: 70, unit: "Piece", unitCost: 40 },
                { name: "Pens", quantity: 70, unit: "Piece", unitCost: 10 },
                { name: "Pencil and eraser set", quantity: 14, unit: "Set", unitCost: 100 }
            ]
        },
        // each child: 5 books, 5 pens, 1 set (the detail items) + 1 uniform
        perPerson: () => [
            { item: 0, detail: "Exercise books", quantity: 5 },
            { item: 0, detail: "Pens", quantity: 5 },
            { item: 0, detail: "Pencil and eraser set", quantity: 1 },
            { item: 1, quantity: 1 }
        ]
    },

    // Teacher support kits to 12 teachers
    "SD-000003": {
        details: {
            0: [
                { name: "Teacher guide", quantity: 12, unit: "Piece", unitCost: 450 },
                { name: "Chalk and markers", quantity: 12, unit: "Set", unitCost: 250 },
                { name: "Lesson plan book", quantity: 12, unit: "Piece", unitCost: 200 }
            ]
        },
        perPerson: () => [
            { item: 0, detail: "Teacher guide", quantity: 1 },
            { item: 0, detail: "Chalk and markers", quantity: 1 },
            { item: 0, detail: "Lesson plan book", quantity: 1 }
        ]
    },

    // Seed grants (ETB 40,000) to 8 women: different amounts
    "SD-000004": {
        perPerson: (index) => [
            { item: 0, quantity: 0, value: [6000, 6000, 5000, 5000, 5000, 5000, 4000, 4000][index] || 0 }
        ]
    },

    // Business skills training, 3 sessions: everyone takes part in all 3
    "SD-000005": {
        perPerson: (index, count, items) => {
            const total = items[0].quantity * items[0].unitCost;
            const share = Math.floor((total / count) * 100) / 100;
            const value = index === count - 1 ? Math.round((total - share * (count - 1)) * 100) / 100 : share;
            return [{ item: 0, quantity: items[0].quantity, value }];
        }
    },

    // Hygiene kits to 10 girls: 3 packs of pads, 2 soaps, 2 underwear, 1 bag each
    "SD-000006": {
        details: {
            0: [
                { name: "Sanitary pads", quantity: 30, unit: "Pack", unitCost: 120 },
                { name: "Soap", quantity: 20, unit: "Piece", unitCost: 60 },
                { name: "Underwear", quantity: 20, unit: "Piece", unitCost: 100 },
                { name: "Carry bag", quantity: 10, unit: "Piece", unitCost: 70 }
            ]
        },
        perPerson: () => [
            { item: 0, detail: "Sanitary pads", quantity: 3 },
            { item: 0, detail: "Soap", quantity: 2 },
            { item: 0, detail: "Underwear", quantity: 2 },
            { item: 0, detail: "Carry bag", quantity: 1 }
        ]
    }

};

const refId = (value) => (value && typeof value === "object" ? value._id : value) || null;

const money = (value) => Math.round(Number(value || 0) * 100) / 100;

const enrichServiceDeliveries = async () => {

    console.log("\n== Detail items and beneficiary allocations");

    const units = await lookupMap(ids.admin, "ServiceDelivery", "Unit");
    const list = (await api("GET", "/service-deliveries", { token: ids.admin })).data;

    const itemsPayload = (delivery, plan) =>
        delivery.items.map((item, index) => ({
            _id: item._id,
            serviceCategory: refId(item.serviceCategory),
            serviceType: refId(item.serviceType),
            // follow the service type (trainings are PARTICIPATION now)
            allocationBehavior: item.serviceType?.allocationBehavior || item.allocationBehavior || "CONSUMPTION",
            quantity: item.quantity,
            unit: refId(item.unit),
            unitCost: item.unitCost,
            donor: refId(item.donor),
            donation: refId(item.donation),
            detailItems: ((plan && plan.details?.[index]) || item.detailItems || []).map(detail => {
                const saved = (item.detailItems || []).find(existing => existing.name === detail.name);
                return {
                    ...(saved?._id ? { _id: saved._id } : {}),
                    name: detail.name,
                    quantity: detail.quantity,
                    unit: typeof detail.unit === "string" && units[detail.unit] ? units[detail.unit] : refId(detail.unit),
                    unitCost: detail.unitCost
                };
            })
        }));

    for (const [number, plan] of Object.entries(DELIVERY_ENRICHMENT)) {

        await step(`Delivery ${number}: detail items and allocations`, async () => {

            const found = list.find(item => item.deliveryNumber === number);
            if (!found) throw new Error("delivery not found");

            const path = `/service-deliveries/${found._id}`;
            const before = (await api("GET", path, { token: ids.admin })).data;
            const people = before.beneficiaries || [];

            // 1. Save the detail items (allocations come next, by their ids)
            if (plan.details) {
                await api("PUT", path, {
                    token: ids.admin,
                    body: {
                        allocationMethod: "Shared",
                        items: itemsPayload(before, plan),
                        beneficiaries: people.map(person => refId(person.beneficiary))
                    }
                });
            }

            // 2. One allocation per person per item / detail item
            const saved = (await api("GET", path, { token: ids.admin })).data;
            const items = itemsPayload(saved, null);

            const beneficiaries =
                people.map((person, index) => ({
                    beneficiary: refId(person.beneficiary),
                    status: person.status || "Received",
                    allocations: plan.perPerson(index, people.length, saved.items).map(share => {
                        const item = saved.items[share.item];
                        const detail = share.detail ? (item.detailItems || []).find(entry => entry.name === share.detail) : null;
                        if (share.detail && !detail) throw new Error(`detail item ${share.detail} not saved`);
                        const unitCost = detail ? detail.unitCost : item.unitCost;
                        return {
                            serviceItem: item._id,
                            detailItem: detail ? detail._id : null,
                            quantity: share.quantity,
                            // the value this person received (quantity x unit cost unless given)
                            allocatedValue: share.value ?? money(share.quantity * unitCost)
                        };
                    })
                }));

            await api("PUT", path, {
                token: ids.admin,
                body: { allocationMethod: "Individual", items, beneficiaries }
            });

            const after = (await api("GET", path, { token: ids.admin })).data;
            const allocated = (after.beneficiaries || []).filter(person => (person.allocations || []).length).length;
            if (allocated !== people.length) throw new Error(`allocations saved for ${allocated} of ${people.length}`);
            if (Number(after.totalAmount) !== Number(before.totalAmount)) throw new Error(`total changed ${before.totalAmount} -> ${after.totalAmount}`);

        });

    }

};


// =====================================================
// 8. ENTERPRISES
// =====================================================

const setupEnterprises = async () => {

    console.log("\n== Enterprises and members");

    ids.enterprises = {};
    const enterprise = (key, body) =>
        step(`Enterprise: ${body.name}`, async () => {
            const created = await api("POST", "/enterprises", { token: ids.data, body: { status: "Active", country: "Ethiopia", ...body } });
            ids.enterprises[key] = created.data._id;
        });

    await enterprise("bakery", {
        name: "Tesfa Women Bakery Cooperative", enterpriseType: pick(ids.enterpriseType, "Cooperative"),
        ownershipType: pick(ids.ownership, "Cooperative Ownership"), businessSector: pick(ids.sector, "Food Processing"),
        phone: "0912 345 678", establishedDate: "2026-06-01", description: "Bread and injera for schools and the local market.",
        ...(ids.places.oromia || {})
    });
    await enterprise("crafts", {
        name: "Adama Handicraft Group", enterpriseType: pick(ids.enterpriseType, "Micro Enterprise"),
        ownershipType: pick(ids.ownership, "Partnership"), businessSector: pick(ids.sector, "Handicrafts and Artisans"),
        phone: "0913 222 111", establishedDate: "2026-07-15", description: "Basketry and woven goods.",
        ...(ids.places.oromia || {})
    });

    const women = ids.beneficiaries.filter(item => item.group === "women");
    const member = (enterpriseKey, person, role) =>
        step(`Member: ${person.name} -> ${enterpriseKey} (${role})`, () =>
            api("POST", "/enterprise-members", {
                token: ids.data,
                body: { enterprise: ids.enterprises[enterpriseKey], beneficiary: person.id, memberRole: role, joinedDate: "2026-06-01", status: "Active" }
            }));

    await member("bakery", women[0], "Manager");
    for (const person of women.slice(1, 6)) await member("bakery", person, "Member");
    await member("crafts", women[6], "Manager");
    for (const person of women.slice(7, 10)) await member("crafts", person, "Member");

    await step("Same beneficiary cannot join the same enterprise twice", () =>
        api("POST", "/enterprise-members", {
            token: ids.data,
            body: { enterprise: ids.enterprises.bakery, beneficiary: women[1].id, memberRole: "Member", joinedDate: "2026-06-01" }
        }).then(() => { throw new Error("duplicate membership accepted"); }, error => { if (!/40\d/.test(error.message)) throw error; }));

};


// =====================================================
// 9. EXPENSES, REVISION
// =====================================================

const lineId = async (budgetKey, category) => {
    const budget = (await api("GET", `/budgets/${ids.budgets[budgetKey]}`, { token: ids.finance })).data;
    const found = budget.summary.lines.find(item => item.category === category);
    if (!found) throw new Error(`line ${category} not in ${budgetKey}`);
    return found._id;
};

const setupExpenses = async () => {

    console.log("\n== Expenses (data entry records, finance approves)");

    ids.expenses = {};

    const expense = (key, budgetKey, category, body, { approve = true, submit = true, approveBody } = {}) =>
        step(`Expense: ${body.description}`, async () => {
            const created = await api("POST", "/expenses", {
                token: ids.data,
                body: { budget: ids.budgets[budgetKey], budgetLine: await lineId(budgetKey, category), paymentMethod: "Bank Transfer", currency: "ETB", ...body }
            });
            ids.expenses[key] = created.data._id;
            if (submit) await api("POST", `/expenses/${created.data._id}/submit`, { token: ids.data });
            if (approve) await api("POST", `/expenses/${created.data._id}/approve`, { token: ids.finance, body: approveBody || { comment: "Receipts checked." } });
        });

    await expense("t1", "teachers", "Personnel", { description: "Master trainer salaries, January-March", expenseDate: "2026-03-31", amount: 150000, payee: "Payroll", donation: ids.donations.teachers });
    await expense("t2", "teachers", "Training & Workshops", { description: "Cluster workshop, Debre Berhan (hall and meals)", expenseDate: "2026-04-16", amount: 69000, payee: "Debre Berhan Teachers College", donation: ids.donations.teachers, activity: ids.activities.teachers, referenceNumber: "INV-0412" });
    await expense("t3", "teachers", "Travel & Per Diem", { description: "Per diem for 40 teachers, 3 days", expenseDate: "2026-04-16", amount: 72000, paymentMethod: "Cash", donation: ids.donations.teachers, activity: ids.activities.teachers });
    await expense("t4", "teachers", "Supplies & Materials", { description: "Printing of training manuals", expenseDate: "2026-04-05", amount: 15750, payee: "Mega Printing", donation: ids.donations.teachers });
    await expense("t5", "teachers", "Personnel", { description: "Master trainer salaries, April-June", expenseDate: "2026-06-30", amount: 150000, payee: "Payroll" }, { approve: false });

    await expense("m1", "materials", "Direct Beneficiary Support", { description: "School meals, Term 1 (600 children)", expenseDate: "2026-03-20", amount: 280000, payee: "Local suppliers", donation: ids.donations.materials, activity: ids.activities.feeding });
    await expense("m2", "materials", "Supplies & Materials", { description: "Exercise books and pens, 2,000 sets", expenseDate: "2026-02-28", amount: 120000, payee: "Bole Stationery", donation: ids.donations.materials });

    // Over the line: refused unless approved deliberately with a reason
    await expense("m3", "materials", "Supplies & Materials", { description: "Grade 4 textbooks", expenseDate: "2026-09-10", amount: 150000, payee: "Educational Publishers" }, { approve: false });
    await step("Over-budget approval is refused without a reason", () =>
        api("POST", `/expenses/${ids.expenses.m3}/approve`, { token: ids.finance, body: {} })
            .then(() => { throw new Error("over-budget expense approved silently"); }, error => { if (!/400|409/.test(error.message)) throw error; }));
    await step("Over-budget approval with a reason", () =>
        api("POST", `/expenses/${ids.expenses.m3}/approve`, { token: ids.finance, body: { allowOverBudget: true, comment: "New curriculum; the director approved the extra 20,000." } }));

    await expense("s1", "savings", "Direct Beneficiary Support", { description: "Seed grants to 8 savings group members", expenseDate: "2026-05-20", amount: 40000, donation: ids.donations.savings, activity: ids.activities.savings });
    await expense("s2", "savings", "Training & Workshops", { description: "Financial literacy training, Adama", expenseDate: "2026-05-07", amount: 48000, payee: "Adama Youth Center", donation: ids.donations.savings, activity: ids.activities.savings });
    await expense("s3", "savings", "Travel & Per Diem", { description: "Field monitoring per diem (draft)", expenseDate: "2026-10-05", amount: 12000, paymentMethod: "Cash" }, { approve: false, submit: false });
    await expense("s4", "savings", "Administration & Overhead", { description: "Office stationery", expenseDate: "2026-09-25", amount: 8000, paymentMethod: "Cash" }, { approve: false });
    await step("Finance returns an expense with a comment", () =>
        api("POST", `/expenses/${ids.expenses.s4}/return`, { token: ids.finance, body: { comment: "Please attach the receipt." } }));

    // Foreign currency: needs an exchange rate
    await step("Foreign-currency expense without a rate is refused", () =>
        lineId("water", "Equipment").then(budgetLine =>
            api("POST", "/expenses", {
                token: ids.data,
                body: { budget: ids.budgets.water, budgetLine, description: "Solar pump without rate", expenseDate: "2026-05-02", amount: 9500, currency: "USD", paymentMethod: "Bank Transfer" }
            }))
            .then(() => { throw new Error("USD expense without a rate accepted"); }, error => { if (!/400/.test(error.message)) throw error; }));
    await expense("w1", "water", "Equipment", { description: "Solar water pump (imported)", expenseDate: "2026-05-02", amount: 9500, currency: "USD", exchangeRate: 125, payee: "SunWater Ltd", donation: ids.donations.water, activity: ids.activities.water });
    await expense("w2", "water", "Consultancy & Services", { description: "Hydro-geological survey", expenseDate: "2026-04-10", amount: 180000, payee: "Afar Geo Consult", donation: ids.donations.water });
    await expense("w3", "water", "Consultancy & Services", { description: "Hydro-geological survey (entered twice)", expenseDate: "2026-04-10", amount: 180000, payee: "Afar Geo Consult" });
    await step("Finance voids the duplicate expense", () =>
        api("POST", `/expenses/${ids.expenses.w3}/void`, { token: ids.finance, body: { comment: "Duplicate of the survey payment." } }));

    await step("Data entry cannot approve expenses (403)", () =>
        api("POST", `/expenses/${ids.expenses.t5}/approve`, { token: ids.data, body: {}, expect: 403 }));

    // Budget figures after spending
    const teachers = (await api("GET", `/budgets/${ids.budgets.teachers}`, { token: ids.finance })).data.summary;
    check("Teacher budget: spent counts approved only (306,750)", teachers.totalSpent === 306750, `spent ${teachers.totalSpent}`);
    check("Teacher budget: pending shows the submitted salary (150,000)", teachers.totalPending === 150000, `pending ${teachers.totalPending}`);
    const water = (await api("GET", `/budgets/${ids.budgets.water}`, { token: ids.finance })).data.summary;
    check("Water budget: USD expense converted (9,500 x 125) and void excluded", water.totalSpent === 1367500, `spent ${water.totalSpent}`);

    // Revision of an approved budget
    await step("Budget revision: start, edit with reason, submit, approve", async () => {
        const budget = (await api("POST", `/budgets/${ids.budgets.water}/revision`, { token: ids.finance })).data;
        const lines = budget.revision.lines.map(item => ({
            _id: item._id, category: item.category, description: item.description,
            amounts: item.amounts.map(amount => ({
                fiscalYear: amount.fiscalYear,
                amount: item.category === "Equipment" && amount.fiscalYear === 2026 ? amount.amount + 300000 : amount.amount
            }))
        }));
        await api("PUT", `/budgets/${ids.budgets.water}/revision`, {
            token: ids.finance,
            body: { reason: "Imported pump prices rose about 20%; one more pump needed in 2026.", startYear: budget.revision.startYear, endYear: budget.revision.endYear, lines }
        });
        await api("POST", `/budgets/${ids.budgets.water}/revision/submit`, { token: ids.finance });
        const approved = (await api("POST", `/budgets/${ids.budgets.water}/revision/approve`, { token: ids.admin, body: { comment: "Approved." } })).data;
        if (approved.version !== 2) throw new Error(`expected version 2, got ${approved.version}`);
    });
    const revised = (await api("GET", `/budgets/${ids.budgets.water}`, { token: ids.finance })).data;
    check("After the revision: v2, old figures kept, expenses still counted",
        revised.version === 2 && revised.versions.length === 1 && revised.summary.totalSpent === 1367500,
        `version ${revised.version}, versions ${revised.versions?.length}, spent ${revised.summary.totalSpent}`);

};


// =====================================================
// 10. TRACE, REPORTS, DASHBOARD, VIEWER
// =====================================================

const REPORT_FILTERS = () => ({
    beneficiaryHistoryReport: `&beneficiary=${ids.beneficiaries[0]?.id}`,
    activityRunReport: `&activityRun=${ids.runs.teachers1}`,
    activityReport: `&activity=${ids.activities.teachers}`,
    enterpriseImpactReport: `&enterprise=${ids.enterprises.bakery}`,
    donorImpactReport: `&donor=${ids.donors.gef}`,
    programImpactReport: `&program=${ids.programs.edu}`
});

const setupReports = async () => {

    console.log("\n== Donation trace, reports, exports, dashboard, viewer");

    await step("Donation trace: where the teacher grant went", async () => {
        const trace = await api("GET", `/donation-trace/donations/${ids.donations.teachers}`, { token: ids.admin });
        if (!trace.data) throw new Error("empty trace");
    });
    await step("Untraced spending list loads", () => api("GET", "/donation-trace/untraced", { token: ids.admin }));
    await step("Program shows its budget from the Budgets module", async () => {
        const program = (await api("GET", `/programs/${ids.programs.edu}`, { token: ids.admin })).data;
        if (program.budget?.approvedAmount !== 9200000) throw new Error(`approved ${program.budget?.approvedAmount}`);
    });

    const catalog = await step("Report catalog loads", () => api("GET", "/reports", { token: ids.admin }));
    const keys = Array.isArray(catalog?.data) ? catalog.data : [];
    console.log(`  reports in catalog: ${keys.length}`);

    const filters = REPORT_FILTERS();
    for (const key of keys) {
        await step(`Report: ${key}`, async () => {
            const report = await api("GET", `/reports/${key}?period=annual&year=2026${filters[key] || ""}`, { token: ids.admin });
            if (!report.data) throw new Error("no data");
        });
    }

    for (const key of ["projectReport", "budgetVsActualReport", "serviceDeliveryReport", "beneficiaryReport"]) {
        for (const format of ["excel", "pdf", "csv"]) {
            await step(`Export ${key} as ${format}`, async () => {
                const response = await fetch(`${API}/reports/${key}?period=annual&year=2026&format=${format}`, { headers: { Authorization: `Bearer ${ids.admin}` } });
                if (response.status !== 200) throw new Error(`${response.status} ${(await response.text()).slice(0, 150)}`);
                const size = (await response.arrayBuffer()).byteLength;
                if (size < 200) throw new Error(`file too small (${size} bytes)`);
            });
        }
    }

    // Viewer: can read, cannot change
    for (const path of ["/programs", "/projects", "/beneficiaries", "/budgets", "/expenses", "/service-deliveries", "/donations"]) {
        await step(`Viewer can read ${path}`, () => api("GET", path, { token: ids.viewer }));
    }
    await step("Viewer cannot approve an expense (403)", () =>
        api("POST", `/expenses/${ids.expenses.t5}/approve`, { token: ids.viewer, body: {}, expect: 403 }));

};


// =====================================================
// MAIN
// =====================================================

const PHASES = [
    setupOrganization,
    setupLookups,
    setupProgramsAndDonors,
    setupBudgets,
    setupActivities,
    setupBeneficiaries,
    setupServiceDeliveries,
    enrichServiceDeliveries,
    setupEnterprises,
    setupExpenses,
    setupReports
];

const main = async () => {

    const remote = Boolean(argument("--uri-file") || argument("--db"));

    if (RESET && (remote || !/localhost|127.0.0.1/.test(API))) {
        throw new Error("--reset is only allowed on the local database and local API.");
    }

    await connectForScript();
    console.log(`Database: ${mongoose.connection.name}   API: ${API}`);

    // Existing demo data: only add detail items and allocations
    if (ENRICH_ONLY) {
        ids.admin = await step("Login as organization admin", () => login(`admin@${DOMAIN}`));
        if (ids.admin) await enrichServiceDeliveries();
        const failed = results.filter(item => item.status === "FAIL");
        console.log(`
== Summary: ${results.length - failed.length} passed, ${failed.length} failed`);
        for (const item of failed) console.log(`  FAIL ${item.name} - ${item.detail}`);
        process.exitCode = failed.length ? 1 : 0;
        return;
    }

    // Never create the demo organization twice
    if (!RESET && await mongoose.connection.db.collection("organizations").findOne({ email: `info@${DOMAIN}` })) {
        throw new Error(`The demo organization (info@${DOMAIN}) already exists in this database.`);
    }

    if (RESET) {
        if (!CONFIRMED) throw new Error("--reset deletes all organization data. Add --yes to confirm.");
        console.log("\n== Reset (plans, locations and super admins kept)");
        await resetDatabase();
    }

    try {
        for (const phase of PHASES) {
            await phase();
        }
    }
    finally {
        await removeTempSuperAdmin();
    }

    const failed = results.filter(item => item.status === "FAIL");
    console.log(`\n== Summary: ${results.length - failed.length} passed, ${failed.length} failed`);
    for (const item of failed) console.log(`  FAIL ${item.name} - ${item.detail}`);

    process.exitCode = failed.length ? 1 : 0;

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
