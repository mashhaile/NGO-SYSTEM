// =====================================================
// HOPE TEST DATA (large) - LOCAL ONLY
// =====================================================
//
// Clears the records of the demo organization "Hope for
// Ethiopia Development Association" (info@heda-demo.org)
// and builds a large test set THROUGH THE API, so every
// rule (dates, balances, currencies, phases) is applied:
//
//   20 donors, 60 donations (ETB / USD / EUR / GBP / CHF)
//   5 programs, 38 projects (one runs in 2 phases)
//   5 program budgets + project budgets (approved), expenses
//   50 activities, 150 activity runs
//   500 beneficiaries, enrollments, 20 attendance sessions
//   service deliveries of every kind (individual, shared,
//   cash, training, household, group, institution, detail
//   items, foreign currency, bought with an expense,
//   cancelled)
//
// Kept: the organization, its users (logins), lookups and
// subscription. Other organizations are not touched.
//
//   node scripts/seedHopeTestData.js --yes
//
// The backend must be running (API_URL, default
// http://localhost:5000/api/v1). Refused for anything but
// the local database. Take a backup first
// (scripts/backupDatabase.js).
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript, argument } = require("../utils/scriptConnection");


const API = process.env.API_URL || "http://localhost:5000/api/v1";
const PASSWORD = "Demo2026pass";
const ORG_EMAIL = "info@heda-demo.org";
const KEEP = ["organizations", "users", "lookups", "subscriptions", "plans", "adminareas"];
const TODAY = new Date(Date.now() + 3 * 60 * 60 * 1000).toISOString().slice(0, 10);


// ---------------------------------------------------------------- helpers

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
    if (response.status >= 300) {
        const error = new Error(`${method} ${path} -> ${response.status} ${data?.message || ""}`);
        error.status = response.status;
        throw error;
    }
    return data?.data ?? data;
};

// run, count, keep going on a failure
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

// a few at a time
const inBatches = async (list, size, fn) => {
    const out = [];
    for (let i = 0; i < list.length; i += size) {
        out.push(...await Promise.all(list.slice(i, i + size).map((item, j) => fn(item, i + j))));
    }
    return out;
};

const list = (data) => (Array.isArray(data) ? data : data?.items || data?.data || []);
const yearly = (values) => Object.entries(values).map(([fiscalYear, amount]) => ({ fiscalYear: Number(fiscalYear), amount }));
const pick = (array, index) => array[index % array.length];
const pad = (n) => String(n).padStart(2, "0");
const date = (month, dayOfMonth) => `2026-${pad(month)}-${pad(dayOfMonth)}`;
const oid = () => new mongoose.Types.ObjectId().toString();
const money = (value) => Math.round(value * 100) / 100;

const section = (title) => console.log(`\n== ${title}`);


// ---------------------------------------------------------------- 1. clear

const clearHope = async () => {

    section("Clear Hope's records (organization, users, lookups and subscription kept)");

    const db = mongoose.connection.db;
    const org = await db.collection("organizations").findOne({ email: ORG_EMAIL });
    if (!org) throw new Error(`Organization ${ORG_EMAIL} not found in ${mongoose.connection.name}.`);

    for (const { name } of await db.listCollections().toArray()) {
        if (KEEP.includes(name)) continue;
        const result = await db.collection(name).deleteMany({ organization: org._id });
        if (result.deletedCount) console.log(`  ${name}: ${result.deletedCount} removed`);
    }

    return org;

};


// ---------------------------------------------------------------- data plans

const PROGRAMS = [
    { key: "edu", name: "Education Quality Improvement", category: "Education", target: 6000, region: 0,
        projects: ["Teacher Professional Development", "Learning Materials Support", "School Feeding", "Girls Education Scholarships", "Early Childhood Learning Centers", "School WASH Facilities", "Adult Literacy Classes", "Inclusive Education for Children with Disabilities"] },
    { key: "liv", name: "Women and Youth Livelihoods", category: "Livelihoods", target: 4000, region: 1,
        projects: ["Women Savings and Credit Groups", "Youth Vocational Skills", "Small Business Start-up Grants", "Urban Agriculture for Women", "Dairy Cooperatives", "Market Linkage for Smallholders", "Digital Skills for Youth", "Handicraft Producer Groups"] },
    { key: "wash", name: "WASH and Climate Resilience", category: "WASH", target: 8000, region: 2,
        projects: ["Community Water Points", "Sanitation and Hygiene Promotion", "Rainwater Harvesting", "Drought Early Warning", "Climate-Smart Agriculture", "Solar Water Pumps", "Water Committee Strengthening"] },
    { key: "health", name: "Maternal and Child Health", category: "Health", target: 5000, region: 3,
        projects: ["Antenatal Care Outreach", "Child Nutrition Screening", "Community Health Volunteers", "Mobile Health Clinics", "Family Planning Awareness", "Health Post Equipment", "Hygiene Kits for Mothers"] },
    { key: "protect", name: "Child Protection and Inclusion", category: "Protection", target: 3000, region: 4,
        projects: ["Child-Friendly Spaces", "Orphans and Vulnerable Children Support", "Disability Inclusion", "Community Protection Committees", "Psychosocial Support", "Street Children Reintegration"] }
];

const DONOR_NAMES = [
    ["Global Education Fund", "Foundation", "United Kingdom"], ["Womens Empowerment Foundation", "NGO", "Netherlands"],
    ["Addis Community Trust", "Organization", "Ethiopia"], ["Swiss Development Partners", "Government", "Switzerland"],
    ["Nordic Water Alliance", "Foundation", "Norway"], ["Hope Diaspora Network", "Organization", "United States"],
    ["European Health Initiative", "Government", "Belgium"], ["Child Rights International", "NGO", "Germany"],
    ["Ethio Telecom Foundation", "Corporate", "Ethiopia"], ["Rotary Club of Addis Ababa", "Organization", "Ethiopia"],
    ["Green Climate Partners", "Foundation", "Denmark"], ["Bright Future Trust", "Foundation", "Canada"],
    ["African Youth Fund", "NGO", "Kenya"], ["Mothers First Alliance", "NGO", "France"],
    ["Dashen Bank Social Fund", "Corporate", "Ethiopia"], ["Water for Life", "Foundation", "Switzerland"],
    ["Abebe Kebede", "Individual", "Ethiopia"], ["Sara Mekonnen", "Individual", "United States"],
    ["Learning Without Borders", "NGO", "Sweden"], ["Friends of Ethiopia", "Organization", "United Kingdom"]
];

const FEMALE = ["Almaz", "Tigist", "Meseret", "Hana", "Selam", "Bethlehem", "Mekdes", "Tsehay", "Aster", "Genet", "Hiwot", "Rahel", "Kidist", "Yeshi", "Zenebech", "Lemlem", "Birtukan", "Saba", "Eden", "Martha", "Feven", "Liya", "Ruth", "Sifan", "Chaltu", "Ayantu", "Lensa", "Hawi"];
const MALE = ["Abebe", "Bekele", "Dawit", "Getachew", "Haile", "Kebede", "Mulugeta", "Solomon", "Tesfaye", "Yonas", "Girma", "Tadesse", "Alemayehu", "Fikadu", "Berhanu", "Henok", "Kaleb", "Natnael", "Biruk", "Abdi", "Lelisa", "Gemechu"];
const FATHERS = ["Alemu", "Bekele", "Demissie", "Gebre", "Hailu", "Kassa", "Mekonnen", "Negash", "Tefera", "Wolde", "Ayele", "Desta", "Assefa", "Worku", "Tolosa", "Gudeta", "Hussen", "Mohammed"];
const GRANDFATHERS = ["Abera", "Bayu", "Chala", "Derese", "Endale", "Fanta", "Gutema", "Jemal", "Lema", "Mamo", "Regassa", "Shiferaw", "Tola", "Wako", "Yadeta"];

const ACTIVITY_TYPES = ["Training", "Workshop", "Awareness Campaign", "Distribution", "Field Visit", "Monitoring Visit", "Community Dialogue", "Assessment", "Meeting", "Seminar"];

const LINES = [
    ["Personnel", "Project staff salaries", 0.30],
    ["Training & Workshops", "Trainings and workshops", 0.20],
    ["Travel & Per Diem", "Field travel and per diem", 0.10],
    ["Supplies & Materials", "Supplies, kits and materials", 0.15],
    ["Direct Beneficiary Support", "Cash and in-kind support", 0.18],
    ["Administration & Overhead", "Office running costs", 0.07]
];


// ---------------------------------------------------------------- main

const main = async () => {

    if (!process.argv.includes("--yes")) throw new Error("This clears Hope's records. Add --yes to confirm.");
    if (argument("--uri-file") || argument("--db") || !/localhost|127\.0\.0\.1/.test(API)) throw new Error("Local database and local API only.");

    await connectForScript();
    if (!/localhost|127\.0\.0\.1/.test(mongoose.connection.host)) throw new Error("Local database only.");
    console.log(`Database: ${mongoose.connection.name}   API: ${API}   today ${TODAY}`);

    await clearHope();

    const login = async (email) => (await api("POST", "/auth/login", null, { email, password: PASSWORD })).token;
    const admin = await login("admin@heda-demo.org");
    const data = await login("data@heda-demo.org");
    const finance = await login("finance@heda-demo.org");

    // ---------------- lookups and places
    section("Lookups and locations");
    const lookups = async (module, category) => list(await api("GET", `/lookups/module/${module}/category/${category}`, admin));
    const byValue = (rows) => Object.fromEntries(rows.map(row => [row.value, row._id]));
    const gender = byValue(await lookups("Beneficiary", "Gender"));
    const education = byValue(await lookups("Beneficiary", "EducationLevel"));
    const occupation = byValue(await lookups("Beneficiary", "Occupation"));
    const marital = byValue(await lookups("Beneficiary", "MaritalStatus"));
    const disability = Object.values(byValue(await lookups("Beneficiary", "DisabilityType")))[0] || null;
    const serviceTypes = await lookups("ServiceDelivery", "ServiceType");
    const units = byValue(await lookups("ServiceDelivery", "Unit"));

    const locations = async (query) => list(await api("GET", `/locations?${query}`, admin));
    const regions = await locations("level=1");
    const wanted = ["Amhara", "Oromia", "Afar", "Sidama", "Tigray", "Somali", "Addis Ababa"];
    const places = [];
    for (const name of wanted) {
        const region = regions.find(item => item.name === name);
        if (!region) continue;
        const zones = await locations(`level=2&parent=${region.pcode}`);
        for (const zone of zones.slice(0, 2)) {
            const woredas = await locations(`level=3&parent=${zone.pcode}`);
            const woreda = woredas[0] || { name: "", pcode: "" };
            places.push({ region: region.name, regionCode: region.pcode, zone: zone.name, zoneCode: zone.pcode, woreda: woreda.name, woredaCode: woreda.pcode });
        }
    }
    console.log(`  ${places.length} places in ${[...new Set(places.map(item => item.region))].join(", ")}`);
    const placeOf = (programIndex, n) => places[(programIndex * 2 + (n % 2)) % places.length];

    const item = (typeName, unitName, quantity, unitCost, extra = {}) => {
        const type = serviceTypes.find(row => row.value === typeName);
        if (!type) throw new Error(`service type ${typeName} not found`);
        return { _id: oid(), serviceCategory: String(type.parentLookup?._id || type.parentLookup), serviceType: type._id, quantity, unit: units[unitName], unitCost, ...extra };
    };

    // ---------------- donors
    section("20 donors");
    const donors = await inBatches(DONOR_NAMES, 5, ([name, donorType, country], i) =>
        attempt(`donor ${name}`, () => api("POST", "/donors", admin, {
            name, donorType, country, status: "Active", donorSince: `20${20 + (i % 6)}-0${1 + (i % 9)}-15`,
            email: `contact${i + 1}@donor-test.org`, contactPerson: `Contact ${i + 1}`, phone: `+251 11 55${String(1000 + i)}`
        })));
    console.log(`  ${donors.filter(Boolean).length} donors`);

    // ---------------- programs and projects (one in phases)
    section("5 programs, 38 projects");
    const programs = [];
    const projects = [];
    for (const [p, plan] of PROGRAMS.entries()) {
        const program = await attempt(`program ${plan.name}`, () => api("POST", "/programs", admin, {
            name: plan.name, category: plan.category, targetBeneficiaries: plan.target,
            description: `${plan.name}: test program.`, startDate: "2026-01-01", endDate: "2028-12-31", status: "Active"
        }));
        if (!program) continue;
        programs.push({ ...plan, id: program._id, index: p });

        for (const [j, name] of plan.projects.entries()) {
            const endDate = j % 3 === 0 ? "2028-12-31" : "2027-12-31";
            const created = await attempt(`project ${name}`, () => api("POST", "/projects", admin, {
                program: program._id, name, description: `${name} (${plan.name}).`,
                donor: donors[(p * 4 + j) % donors.length]?._id || null,
                startDate: "2026-01-01", endDate, status: "Active"
            }));
            if (created) projects.push({ id: created._id, name, program: programs[programs.length - 1], index: projects.length, endDate, main: false });
        }
    }

    // "Community Water Points" runs in 2 phases (Phase 1: 2026, Phase 2: 2027)
    const waterMain = projects.find(project => project.name === "Community Water Points");
    if (waterMain) {
        waterMain.main = true;
        for (const [n, [start, end]] of [["2026-01-01", "2026-12-31"], ["2027-01-01", "2027-12-31"]].entries()) {
            const created = await attempt(`phase ${n + 1}`, () => api("POST", "/projects", admin, {
                program: waterMain.program.id, parentProject: waterMain.id, name: `Community Water Points - Phase ${n + 1}`,
                startDate: start, endDate: end, status: n === 0 ? "Active" : "Planned"
            }));
            if (created) projects.push({ id: created._id, name: `Community Water Points - Phase ${n + 1}`, program: waterMain.program, index: projects.length, endDate: end, phase: n + 1, main: false });
        }
    }
    console.log(`  ${programs.length} programs, ${projects.length} projects (Community Water Points in 2 phases)`);

    // where 2026 work can be recorded (not the main project, not Phase 2)
    const workProjects = projects.filter(project => !project.main && project.phase !== 2);

    // ---------------- donations (60)
    section("60 donations");
    const FOREIGN = [["USD", 120], ["EUR", 140], ["GBP", 160], ["CHF", 145]];
    const donations = [];
    for (let i = 0; i < 60; i++) {
        const project = i < workProjects.length ? workProjects[i] : workProjects[(i * 7) % workProjects.length];
        const foreign = i % 9 === 4 ? FOREIGN[(i / 9 | 0) % FOREIGN.length] : null;
        const pledged = i % 15 === 14;
        const unrestricted = i % 20 === 19;
        const currency = foreign ? foreign[0] : "ETB";
        const amount = foreign ? 20000 + (i % 5) * 10000 : 1500000 + (i % 7) * 350000;
        const created = await attempt(`donation ${i + 1}`, () => api("POST", "/donations", admin, {
            title: `${project.name} grant ${i < workProjects.length ? 2026 : "top-up"}${foreign ? ` (${currency})` : ""}`,
            donor: donors[i % donors.length]?._id, program: project.program.id, project: unrestricted ? null : project.id,
            amount, currency, donationDate: date(1 + (i % 8), 5 + (i % 20)),
            fundingSource: i % 4 === 0 ? "Donation" : "Grant", fundingRestriction: unrestricted ? "Unrestricted" : "Restricted",
            donationType: "Bank Transfer", status: pledged ? "Pledged" : "Received", receiptNumber: pledged ? null : `RC-26-${String(i + 1).padStart(3, "0")}`,
            receivedRate: foreign && !pledged ? foreign[1] : null
        }));
        if (created) donations.push({ id: created._id, project: unrestricted ? null : project.id, currency, amount, pledged, rate: foreign?.[1] || null, used: 0 });
    }
    console.log(`  ${donations.length} donations (${donations.filter(item => item.currency !== "ETB").length} in USD/EUR/GBP/CHF, ${donations.filter(item => item.pledged).length} pledged)`);

    // a received ETB donation of this project with room for `amount`
    const etbDonationFor = (projectId, amount) => {
        const found = donations.find(item => item.project === String(projectId) && item.currency === "ETB" && !item.pledged && item.amount - item.used >= amount);
        if (found) found.used += amount;
        return found?.id || null;
    };

    // ---------------- budgets (program ceilings + one per project / phase)
    section("Budgets: 5 program budgets, project budgets (approved)");
    const budgets = {};
    const totals = new Map();
    const projectBudgets = [];
    for (const project of projects.filter(item => !item.main)) {
        const base = 1200000 + (project.index % 6) * 250000;
        const years = project.phase === 1 ? [2026] : project.phase === 2 ? [2027] : [2026, 2027];
        const lines = LINES.map(([category, description, share]) => ({
            category, description,
            amounts: yearly(Object.fromEntries(years.map(year => [year, Math.round(base * share / 1000) * 1000])))
        }));
        projectBudgets.push({ project, years, lines });
        const sum = totals.get(project.program.id) || {};
        for (const year of years) sum[year] = (sum[year] || 0) + lines.reduce((total, line) => total + line.amounts.find(amount => amount.fiscalYear === year).amount, 0);
        totals.set(project.program.id, sum);
    }
    for (const program of programs) {
        const sum = totals.get(program.id) || {};
        const amounts = { 2026: Math.ceil((sum[2026] || 0) * 1.15 / 100000) * 100000, 2027: Math.ceil((sum[2027] || 0) * 1.15 / 100000) * 100000, 2028: 2000000 };
        await attempt(`program budget ${program.name}`, async () => {
            const created = await api("POST", "/budgets", finance, { level: "program", name: `${program.name} Budget 2026-2028`, program: program.id, currency: "ETB", startYear: 2026, endYear: 2028, yearlyAmounts: yearly(amounts) });
            await api("POST", `/budgets/${created._id}/submit`, finance);
            await api("POST", `/budgets/${created._id}/approve`, admin, { comment: "Approved by the board." });
        });
    }
    await inBatches(projectBudgets, 4, ({ project, years, lines }) =>
        attempt(`project budget ${project.name}`, async () => {
            const created = await api("POST", "/budgets", finance, {
                level: "project", name: `${project.name} Budget`, project: project.id, currency: "ETB",
                startYear: years[0], endYear: years[years.length - 1], lines
            });
            await api("POST", `/budgets/${created._id}/submit`, finance);
            const approved = await api("POST", `/budgets/${created._id}/approve`, admin, { comment: "Within the program ceiling." });
            budgets[project.id] = { id: created._id, lines: (approved.summary?.lines || approved.lines || []) };
        }));
    // the line ids (from the saved budget)
    for (const project of Object.keys(budgets)) {
        const saved = await api("GET", `/budgets/${budgets[project].id}`, finance);
        budgets[project].lines = saved.summary.lines;
    }
    console.log(`  ${Object.keys(budgets).length} project budgets approved`);

    // ---------------- expenses
    section("Expenses (data entry records, finance approves)");
    const lineOf = (projectId, category) => budgets[projectId]?.lines.find(row => row.category === category)?._id;
    const expensePlan = [];
    for (const project of workProjects) {
        if (!budgets[project.id]) continue;
        expensePlan.push(
            { project, category: "Personnel", description: "Staff salaries, January-March", amount: 90000 + (project.index % 4) * 10000, day: date(3, 31), state: "Approved" },
            { project, category: "Training & Workshops", description: "Training venue and meals", amount: 45000 + (project.index % 5) * 5000, day: date(4 + (project.index % 4), 12), state: "Approved" },
            { project, category: "Travel & Per Diem", description: "Field monitoring per diem", amount: 15000 + (project.index % 3) * 4000, day: date(6, 20), state: project.index % 5 === 0 ? "Draft" : project.index % 7 === 0 ? "Returned" : "Approved" }
        );
    }
    await inBatches(expensePlan, 4, (plan) =>
        attempt(`expense ${plan.project.name} ${plan.category}`, async () => {
            const budgetLine = lineOf(plan.project.id, plan.category);
            const created = await api("POST", "/expenses", data, {
                budget: budgets[plan.project.id].id, budgetLine, description: plan.description, expenseDate: plan.day,
                amount: plan.amount, currency: "ETB", paymentMethod: plan.category === "Travel & Per Diem" ? "Cash" : "Bank Transfer",
                donation: plan.state === "Draft" ? null : etbDonationFor(plan.project.id, plan.amount)
            });
            if (plan.state === "Draft") return;
            await api("POST", `/expenses/${created._id}/submit`, data);
            if (plan.state === "Returned") return api("POST", `/expenses/${created._id}/return`, finance, { comment: "Please attach the receipt." });
            return api("POST", `/expenses/${created._id}/approve`, finance, { comment: "Receipts checked." });
        }));
    // one in USD on an ETB budget
    if (workProjects[1] && budgets[workProjects[1].id]) {
        await attempt("USD expense", async () => {
            const created = await api("POST", "/expenses", data, { budget: budgets[workProjects[1].id].id, budgetLine: lineOf(workProjects[1].id, "Supplies & Materials"), description: "Imported tablets (USD invoice)", expenseDate: date(7, 8), amount: 800, currency: "USD", exchangeRate: 120, paymentMethod: "Bank Transfer" });
            await api("POST", `/expenses/${created._id}/submit`, data);
            await api("POST", `/expenses/${created._id}/approve`, finance, { comment: "OK" });
        });
    }
    console.log(`  ${expensePlan.length + 1} expenses planned`);

    // ---------------- activities (50) and runs (150)
    section("50 activities, 150 activity runs");
    const activities = [];
    for (let i = 0; i < 50; i++) {
        const project = workProjects[i % workProjects.length];
        const type = ACTIVITY_TYPES[i % ACTIVITY_TYPES.length];
        const place = placeOf(project.program.index, i);
        const created = await attempt(`activity ${i + 1}`, () => api("POST", "/activities", admin, {
            project: project.id, name: `${type}: ${project.name}${i >= workProjects.length ? " (round 2)" : ""}`,
            activityType: type, participantSource: type === "Training" || type === "Workshop" ? "Enrolled Beneficiaries" : "Mixed",
            activityDate: date(2 + (i % 6), 3 + (i % 20)), ...place, targetParticipants: 20 + (i % 6) * 10,
            status: i % 4 === 0 ? "Completed" : "Active", description: `${type} for ${project.name}.`
        }));
        if (created) activities.push({ id: created._id, project, type, place, index: i });
    }
    const runs = [];
    await inBatches(activities, 5, (activity) =>
        // one after another: a run code counts the runs of its activity
        inBatches([0, 1, 2], 1, async (n) => {
            const window = [[date(2, 10), date(4, 25), "Completed"], [date(5, 5), date(7, 28), "Completed"], [date(9, 1), "2026-12-15", "Active"]][n];
            const created = await attempt(`run ${activity.index + 1}.${n + 1}`, () => api("POST", "/activity-runs", data, {
                activity: activity.id, name: `Batch ${n + 1} - ${activity.place.woreda || activity.place.zone}`,
                startDate: window[0], endDate: window[1], ...activity.place, status: window[2]
            }));
            if (created) runs.push({ id: created._id, activity, n, start: window[0], end: window[1] });
        }));
    console.log(`  ${activities.length} activities, ${runs.length} runs`);

    // ---------------- beneficiaries (500) and enrollments
    section("500 beneficiaries, enrollments");
    const OCCUPATIONS = { edu: ["Student", "Government Employee"], liv: ["Trader", "Household Work", "Farmer"], wash: ["Farmer", "Household Work"], health: ["Household Work", "Trader"], protect: ["Student", "Unemployed"] };
    const EDUCATION = ["No Formal Education", "Primary Education", "Secondary Education", "Diploma"];
    const plan = Array.from({ length: 500 }, (_, i) => {
        const program = programs[i % programs.length];
        const female = program.key === "health" ? i % 5 !== 0 : i % 3 !== 0;
        const age = program.key === "edu" || program.key === "protect" ? 7 + (i % 14) : 18 + (i * 7) % 50;
        return { i, program, female, age };
    });
    const people = await inBatches(plan, 8, (person) => {
        const firstName = person.female ? pick(FEMALE, person.i * 3) : pick(MALE, person.i * 5);
        const middleName = pick(FATHERS, person.i * 7 + 1);
        const lastName = pick(GRANDFATHERS, person.i * 11 + 2);
        const occupationName = pick(OCCUPATIONS[person.program.key] || ["Farmer"], person.i);
        return attempt(`beneficiary ${person.i + 1}`, async () => {
            const created = await api("POST", "/beneficiaries", data, {
                firstName, middleName, lastName,
                gender: gender[person.female ? "Female" : "Male"],
                dateOfBirth: `${2026 - person.age}-${pad(1 + (person.i % 12))}-${pad(1 + (person.i % 27))}`,
                phone: person.age >= 18 ? `09${String(20000000 + person.i * 104729).slice(-8)}` : "",
                country: "Ethiopia", ...placeOf(person.program.index, person.i), kebele: `Kebele ${pad(1 + (person.i % 12))}`,
                educationLevel: education[pick(EDUCATION, person.i)] || null,
                occupation: occupation[occupationName] || null,
                maritalStatus: marital[person.age >= 22 && person.i % 3 ? "Married" : "Single"] || null,
                isPWD: Boolean(disability) && person.i % 37 === 0,
                disabilityType: disability && person.i % 37 === 0 ? disability : null,
                status: "Active"
            });
            return { id: created._id, ...person };
        });
    });
    const beneficiaries = people.filter(Boolean);
    const enrolled = await inBatches(beneficiaries, 8, (person) =>
        attempt(`enroll ${person.i + 1}`, () => api("POST", "/enrollments", data, {
            program: person.program.id, beneficiary: person.id, enrollmentDate: date(1 + (person.i % 3), 10 + (person.i % 15)), status: "Active"
        })));
    console.log(`  ${beneficiaries.length} beneficiaries, ${enrolled.filter(Boolean).length} enrollments`);
    const peopleOf = (programId, count, offset = 0) => {
        const own = beneficiaries.filter(person => String(person.program.id) === String(programId));
        return Array.from({ length: Math.min(count, own.length) }, (_, k) => own[(offset + k) % own.length]);
    };

    // ---------------- attendance (20 sessions)
    section("20 attendance sessions");
    const trainingRuns = runs.filter(run => ["Training", "Workshop", "Seminar"].includes(run.activity.type) && run.n < 2);
    let sessions = 0;
    for (let s = 0; s < 20 && trainingRuns.length; s++) {
        const run = trainingRuns[s % trainingRuns.length];
        const number = Math.floor(s / trainingRuns.length) + 1;
        const sessionDate = run.n === 0 ? date(2, 12 + number) : date(5, 7 + number);
        const ok = await attempt(`attendance ${s + 1}`, async () => {
            const attendance = await api("POST", "/attendance", data, { activityRun: run.id, sessionTitle: `${run.activity.type} session ${number}`, sessionNumber: number, sessionDate, notes: "" });
            const group = peopleOf(run.activity.project.program.id, 15 + (s % 3) * 5, s * 4);
            await api("POST", `/attendance/${attendance._id}/records`, data, {
                records: group.map((person, k) => ({
                    participantType: "Beneficiary", beneficiary: person.id, gender: person.female ? "Female" : "Male",
                    ageGroup: person.age < 15 ? "Child" : person.age < 30 ? "Youth" : person.age < 60 ? "Adult" : "Elderly",
                    disabilityStatus: person.i % 37 === 0, status: k % 9 === 4 ? "Absent" : "Present"
                }))
            });
        });
        if (ok !== null) sessions++;
    }
    console.log(`  ${sessions} sessions`);

    // ---------------- service deliveries (every kind)
    section("Service deliveries of every kind");
    const runOf = (projectId) => runs.find(run => String(run.activity.project.id) === String(projectId) && run.n < 2);
    const kinds = [];
    const deliver = (label, project, body, when) => {
        const run = runOf(project.id);
        kinds.push(label);
        return attempt(`delivery ${label} (${project.name})`, () => api("POST", "/service-deliveries", data, {
            status: "Delivered", program: project.program.id, project: project.id,
            activity: run?.activity.id || null, activityRun: run?.id || null,
            deliveryDate: when, ...placeOf(project.program.index, project.index), ...body
        }));
    };
    const share = (people, serviceItem, quantity, allocatedValue) =>
        people.map(person => ({ beneficiary: person.id, allocations: [{ serviceItem: serviceItem._id, quantity, ...(allocatedValue === undefined ? {} : { allocatedValue }) }] }));

    let made = 0;
    for (const [k, project] of workProjects.entries()) {
        const group = peopleOf(project.program.id, 6 + (k % 5), k * 3);
        const when = date(3 + (k % 7), 4 + (k % 20));
        const kind = k % 9;
        let result = null;

        if (kind === 0) {
            // goods shared out equally (kits)
            const kits = item("Hygiene Kit", "Set", group.length, 750, { donation: etbDonationFor(project.id, group.length * 750) });
            result = await deliver("Kits shared equally", project, { recipientType: "Individual", allocationMethod: "Shared", items: [kits], beneficiaries: group.map(person => person.id) }, when);
        }
        else if (kind === 1) {
            // goods given per person (25 kg each)
            const food = item("Food Assistance", "Kg", group.length * 25, 80, { donation: etbDonationFor(project.id, group.length * 2000) });
            result = await deliver("Food per person", project, { recipientType: "Individual", allocationMethod: "Individual", items: [food], beneficiaries: share(group, food, 25) }, when);
        }
        else if (kind === 2) {
            // cash, different amounts per person
            const amounts = group.map((_, n) => 3000 + (n % 3) * 1500);
            const total = amounts.reduce((sum, value) => sum + value, 0);
            const cash = item("Cash Assistance", "ETB", 1, total, { donation: etbDonationFor(project.id, total) });
            result = await deliver("Cash per person", project, { recipientType: "Individual", allocationMethod: "Individual", items: [cash], beneficiaries: group.map((person, n) => ({ beneficiary: person.id, allocations: [{ serviceItem: cash._id, quantity: 0, allocatedValue: amounts[n] }] })) }, when);
        }
        else if (kind === 3) {
            // a training: 3 sessions, the cost shared by the participants
            const training = item("Business Skills Training", "Session", 3, 4000, { donation: etbDonationFor(project.id, 12000) });
            result = await deliver("Training (3 sessions)", project, { recipientType: "Individual", allocationMethod: "Individual", items: [training], beneficiaries: share(group, training, 3) }, when);
        }
        else if (kind === 4) {
            // a household, as a whole
            const cash = item("Cash Assistance", "ETB", 1, 6000, { donation: etbDonationFor(project.id, 6000) });
            result = await deliver("Household cash", project, { recipientType: "Household", recipientName: `Household of ${group[0] ? "beneficiary " + (group[0].i + 1) : "a family"}`, allocationMethod: "Group", items: [cash], beneficiaries: group.slice(0, 4).map(person => person.id) }, when);
        }
        else if (kind === 5) {
            // a group / community, as a whole
            const supplies = item("WASH Supplies", "Box", 6, 2500, { donation: etbDonationFor(project.id, 15000) });
            result = await deliver("Community group supplies", project, { recipientType: "Group / Community", recipientName: `${project.name} community committee`, allocationMethod: "Group", items: [supplies], beneficiaries: group.map(person => person.id) }, when);
        }
        else if (kind === 6) {
            // an institution (school / health post), no people listed
            const supplies = item("School Supplies", "Set", 40, 350, { donation: etbDonationFor(project.id, 14000) });
            result = await deliver("Institution supplies", project, { recipientType: "Institution", recipientName: `${project.program.key === "health" ? "Health post" : "Primary school"} ${k + 1}`, allocationMethod: "Unallocated", items: [supplies], beneficiaries: [] }, when);
        }
        else if (kind === 7) {
            // a breakdown into detail items, given per person
            const detail = oid();
            const supplies = item("School Supplies", "Set", group.length, 300, {
                donation: etbDonationFor(project.id, group.length * 300),
                detailItems: [{ _id: detail, name: "Exercise book set", quantity: group.length, unit: units.Set, unitCost: 300 }]
            });
            result = await deliver("Detail items", project, { recipientType: "Individual", allocationMethod: "Individual", items: [supplies], beneficiaries: share(group, supplies, 1).map(row => ({ ...row, allocations: row.allocations.map(allocation => ({ ...allocation, detailItem: detail })) })) }, when);
        }
        else {
            // bought with an expense, then given out (charged once)
            const budgetLine = lineOf(project.id, "Supplies & Materials");
            const cost = group.length * 750;
            const donation = etbDonationFor(project.id, cost);
            const expense = budgetLine && await attempt(`kits expense ${project.name}`, async () => {
                const created = await api("POST", "/expenses", data, { budget: budgets[project.id].id, budgetLine, description: `Hygiene kits purchase (${group.length})`, expenseDate: when, amount: cost, currency: "ETB", paymentMethod: "Bank Transfer", donation });
                await api("POST", `/expenses/${created._id}/submit`, data);
                await api("POST", `/expenses/${created._id}/approve`, finance, { comment: "Kits received." });
                return created;
            });
            const kits = item("Hygiene Kit", "Set", group.length, 750, { donation, paidByExpense: expense?._id || null });
            result = await deliver("Bought with an expense", project, { recipientType: "Individual", allocationMethod: "Shared", items: [kits], beneficiaries: group.map(person => person.id) }, when);
        }
        if (result) made++;
    }

    // in another currency, from a foreign donation of the same project
    for (const donation of donations.filter(item => item.currency !== "ETB" && !item.pledged && item.project).slice(0, 4)) {
        const project = workProjects.find(item => String(item.id) === donation.project);
        if (!project) continue;
        const group = peopleOf(project.program.id, 5, project.index);
        const kits = item("Hygiene Kit", "Set", group.length, 6, { currency: donation.currency, exchangeRate: donation.rate + 5, donation: donation.id });
        if (await deliver(`Kits priced in ${donation.currency}`, project, { recipientType: "Individual", allocationMethod: "Shared", items: [kits], beneficiaries: group.map(person => person.id) }, date(8, 18))) made++;
    }

    // cancelled (kept for audit)
    const cancelledProject = workProjects[2];
    if (cancelledProject) {
        const group = peopleOf(cancelledProject.program.id, 3, 50);
        if (await deliver("Cancelled", cancelledProject, { status: "Cancelled", recipientType: "Individual", allocationMethod: "Shared", items: [item("School Fees", "ETB", 3, 400)], beneficiaries: group.map(person => person.id) }, date(7, 1))) made++;
    }
    console.log(`  ${made} deliveries: ${[...new Set(kinds)].join(", ")}`);

    // ---------------- summary
    console.log(`\n== Done: ${done} records created, ${failures.length} failed`);
    for (const failure of failures.slice(0, 40)) console.log(`  FAIL ${failure}`);
    if (failures.length > 40) console.log(`  ... and ${failures.length - 40} more`);
    process.exitCode = failures.length ? 1 : 0;

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
