// =====================================================
// BENEFICIARIES REPORT
// =====================================================
//
// Who the organization serves, and what they received in
// the period. Replaces the Beneficiary, Beneficiary
// History and Enrollment reports.
//
// Filters: program, project, region, gender, status
//
// =====================================================

const Beneficiary = require("../../../models/Beneficiary");
const Enrollment = require("../../../models/enrollment");
const Attendance = require("../../../models/Attendance");
const AttendanceRecord = require("../../../models/AttendanceRecord");

const {
    scope, objectId, toId, round2, percent, fullName, ageOf, ageGroup, AGE_GROUPS,
    lookupText, locationText, groupRows, summaryItem, column, section, buildReport
} = require("../core");

const { inPeriod, monthKey, monthName } = require("../period");
const { loadDeliveries, loadServedLinks } = require("../data");


const AGE_ORDER = [...AGE_GROUPS.map(group => group.label), "Unknown"];

const PRESENT = ["Present", "Late"];


const generate = async (query, context, period) => {

    const { organizationId } = context;

    // ---------- the people ----------
    const personFilter = {};
    if (query.region) personFilter.$or = [{ region: query.region }, { regionCode: query.region }];
    if (query.status) personFilter.status = query.status;
    if (objectId(query.gender)) personFilter.gender = objectId(query.gender);

    let people =
        await Beneficiary.find(scope(organizationId, personFilter))
            .select("beneficiaryNumber firstName middleName lastName gender dateOfBirth age region zone woreda kebele isPWD vulnerableGroups status createdAt")
            .populate("gender", "value")
            .lean();

    // ---------- what they received in the period ----------
    const deliveryFilter = {};
    if (objectId(query.program)) deliveryFilter.program = objectId(query.program);
    if (objectId(query.project)) deliveryFilter.project = objectId(query.project);

    const deliveries = await loadDeliveries(organizationId, period, deliveryFilter);
    const links = await loadServedLinks(organizationId, deliveries);

    // ---------- enrollments ----------
    const enrollmentFilter = {};
    if (objectId(query.program)) enrollmentFilter.program = objectId(query.program);

    const enrollments =
        await Enrollment.find(scope(organizationId, enrollmentFilter))
            .select("beneficiary program status enrollmentDate completionDate")
            .populate("program", "programCode name")
            .lean();

    // ---------- attendance in the period ----------
    const sessionDate = inPeriod(period);
    const sessionFilter = {};
    if (sessionDate) sessionFilter.sessionDate = sessionDate;
    if (objectId(query.program)) sessionFilter.program = objectId(query.program);
    if (objectId(query.project)) sessionFilter.project = objectId(query.project);

    const sessions =
        await Attendance.find(scope(organizationId, sessionFilter)).select("_id").lean();

    const attendance =
        sessions.length
            ? await AttendanceRecord.find(scope(organizationId, {
                attendance: { $in: sessions.map(item => item._id) },
                beneficiary: { $ne: null },
                status: { $in: PRESENT }
            })).select("beneficiary").lean()
            : [];

    // with a program / project filter: the people in it
    if (objectId(query.program) || objectId(query.project)) {
        const inScope = new Set([
            ...links.map(link => link.beneficiaryId),
            ...(objectId(query.program) ? enrollments.map(item => toId(item.beneficiary)) : []),
            ...attendance.map(item => toId(item.beneficiary))
        ]);
        people = people.filter(person => inScope.has(toId(person._id)));
    }

    // ---------- per person ----------
    const byPerson = new Map(people.map(person => [toId(person._id), {
        person,
        gender: lookupText(person.gender) || "Not specified",
        ageGroup: ageGroup(ageOf(person)),
        location: locationText(person) || "Not specified",
        services: 0,
        value: 0,
        sessions: 0,
        programs: new Set(),
        enrolled: []
    }]));

    for (const link of links) {
        const row = byPerson.get(link.beneficiaryId);
        if (!row) continue;
        row.services += 1;
        row.value += link.value;
        if (link.serviceDelivery.program?.name) row.programs.add(link.serviceDelivery.program.name);
    }

    for (const record of attendance) {
        const row = byPerson.get(toId(record.beneficiary));
        if (row) row.sessions += 1;
    }

    for (const enrollment of enrollments) {
        const row = byPerson.get(toId(enrollment.beneficiary));
        if (!row) continue;
        row.enrolled.push(enrollment);
        if (enrollment.program?.name) row.programs.add(enrollment.program.name);
    }

    const rows = [...byPerson.values()];
    const reached = rows.filter(row => row.services > 0);
    const attended = rows.filter(row => row.sessions > 0);
    const female = rows.filter(row => /^female$/i.test(row.gender)).length;
    const male = rows.filter(row => /^male$/i.test(row.gender)).length;
    const disabled = rows.filter(row => row.person.isPWD).length;
    const periodStart = period.start ? period.start.getTime() : -Infinity;
    const periodEnd = period.end ? period.end.getTime() : Infinity;
    const registeredInPeriod = (row) => {
        const at = new Date(row.person.createdAt).getTime();
        return at >= periodStart && at < periodEnd;
    };
    const activeEnrollments = enrollments.filter(item => item.status === "Active" && byPerson.has(toId(item.beneficiary)));
    const valueReceived = round2(rows.reduce((sum, row) => sum + row.value, 0));

    // ---------- breakdowns ----------
    const measures = {
        registered: () => 1,
        reached: row => (row.services > 0 ? 1 : 0),
        value: row => row.value
    };

    const breakdownColumns = (first) => [
        column("label", first),
        column("registered", "Registered", "number"),
        column("reached", "Reached in period", "number"),
        column("value", "Value received", "money", { currency: "ETB" })
    ];

    const byProgram = new Map();
    for (const enrollment of enrollments) {
        if (!byPerson.has(toId(enrollment.beneficiary))) continue;
        const name = enrollment.program?.name || "No program";
        const row = byProgram.get(name) || { label: name, enrolled: 0, active: 0, completed: 0, reached: new Set(), value: 0 };
        row.enrolled += 1;
        if (enrollment.status === "Active") row.active += 1;
        if (enrollment.status === "Completed") row.completed += 1;
        byProgram.set(name, row);
    }
    for (const link of links) {
        if (!byPerson.has(link.beneficiaryId)) continue;
        const name = link.serviceDelivery.program?.name || "No program";
        const row = byProgram.get(name) || { label: name, enrolled: 0, active: 0, completed: 0, reached: new Set(), value: 0 };
        row.reached.add(link.beneficiaryId);
        row.value += link.value;
        byProgram.set(name, row);
    }

    const byMonth = new Map();
    for (const row of rows) {
        if (!registeredInPeriod(row)) continue;
        const key = monthKey(row.person.createdAt);
        const entry = byMonth.get(key) || { key, registered: 0, reached: new Set(), value: 0 };
        entry.registered += 1;
        byMonth.set(key, entry);
    }
    for (const link of links) {
        if (!byPerson.has(link.beneficiaryId)) continue;
        const key = monthKey(link.serviceDelivery.deliveryDate);
        const entry = byMonth.get(key) || { key, registered: 0, reached: new Set(), value: 0 };
        entry.reached.add(link.beneficiaryId);
        entry.value += link.value;
        byMonth.set(key, entry);
    }

    const vulnerableGroups = groupRows(
        rows.filter(row => (row.person.vulnerableGroups || []).length),
        row => row.person.vulnerableGroups.map(group => lookupText(group)),
        { people: () => 1 }
    );

    return buildReport({
        key: "beneficiaries",
        title: "Beneficiaries",
        description: "Who the organization serves, and what each person received in the period: their own share of every delivery.",
        period,
        summary: [
            summaryItem("Registered beneficiaries", rows.length),
            summaryItem("Female", female, "number", { note: `${percent(female, rows.length)}%` }),
            summaryItem("Male", male, "number", { note: `${percent(male, rows.length)}%` }),
            summaryItem("With a disability", disabled),
            summaryItem("Registered in the period", rows.filter(registeredInPeriod).length),
            summaryItem("Active enrollments", activeEnrollments.length),
            summaryItem("Reached by services", reached.length, "number", { note: `${percent(reached.length, rows.length)}% of registered` }),
            summaryItem("Value received", valueReceived, "money", { currency: "ETB" }),
            summaryItem("Attended training sessions", attended.length)
        ],
        sections: [
            section("gender", "By gender", breakdownColumns("Gender"),
                groupRows(rows, row => row.gender, measures),
                { chart: { type: "pie", x: "label", series: ["registered"] } }),
            section("age", "By age group", breakdownColumns("Age group"),
                groupRows(rows, row => row.ageGroup, measures, { order: AGE_ORDER }),
                { chart: { type: "bar", x: "label", series: ["registered", "reached"] } }),
            section("location", "By location", breakdownColumns("Woreda, zone, region"),
                groupRows(rows, row => row.location, measures)),
            section("program", "By program", [
                column("label", "Program"),
                column("enrolled", "Enrolled", "number"),
                column("active", "Active", "number"),
                column("completed", "Completed", "number"),
                column("reached", "Reached by services", "number"),
                column("value", "Value received", "money", { currency: "ETB" })
            ], [...byProgram.values()]
                .map(row => ({ ...row, reached: row.reached.size, value: round2(row.value) }))
                .sort((a, b) => b.enrolled - a.enrolled || b.reached - a.reached),
            { chart: { type: "bar", x: "label", series: ["enrolled", "reached"] } }),
            section("month", "By month", [
                column("label", "Month"),
                column("registered", "Newly registered", "number"),
                column("reached", "People reached", "number"),
                column("value", "Value received", "money", { currency: "ETB" })
            ], [...byMonth.values()]
                .sort((a, b) => a.key.localeCompare(b.key))
                .map(entry => ({ label: monthName(entry.key), registered: entry.registered, reached: entry.reached.size, value: round2(entry.value) })),
            { chart: { type: "line", x: "label", series: ["reached", "registered"] } }),
            vulnerableGroups.length
                ? section("vulnerable", "Vulnerable groups", [column("label", "Group"), column("people", "People", "number")], vulnerableGroups)
                : null
        ],
        details: {
            title: "Beneficiaries",
            link: { kind: "beneficiary", idKey: "id" },
            columns: [
                column("number", "No."),
                column("name", "Name"),
                column("gender", "Gender"),
                column("age", "Age", "number"),
                column("location", "Location"),
                column("programs", "Programs"),
                column("services", "Services received", "number"),
                column("value", "Value received", "money", { currency: "ETB" }),
                column("sessions", "Sessions attended", "number"),
                column("status", "Status")
            ],
            rows: rows
                .sort((a, b) => String(a.person.beneficiaryNumber).localeCompare(String(b.person.beneficiaryNumber)))
                .map(row => ({
                    id: toId(row.person._id),
                    number: row.person.beneficiaryNumber,
                    name: fullName(row.person),
                    gender: row.gender,
                    age: ageOf(row.person),
                    location: row.location,
                    programs: [...row.programs].join(", "),
                    services: row.services,
                    value: round2(row.value),
                    sessions: row.sessions,
                    status: row.person.status || ""
                }))
        }
    });

};


module.exports = {
    key: "beneficiaries",
    title: "Beneficiaries",
    description: "Who you serve: gender, age, location, programs, and what each person received.",
    filters: ["program", "project", "region", "gender", "status"],
    detail: "beneficiary",
    generate
};
