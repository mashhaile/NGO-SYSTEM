// =====================================================
// CHECK DATES (read-only)
// =====================================================
//
// Lists records whose dates break the date rules (see
// models/plugins/dateRules.js and insideProjectDates.js):
//
//   - an end before its start (programs, projects, activity
//     runs, TORs, enterprises, members, enrollments,
//     attendance check-in / check-out)
//   - work outside its project's dates (activities, runs,
//     deliveries, attendance sessions, TORs); a project
//     outside its program's dates; an attendance session
//     outside its activity run; an enrollment outside its
//     program or before the person was born; a member
//     outside the enterprise's dates
//   - something done in the future (a received donation, a
//     delivered delivery, an expense, a date of birth,
//     donor since / last contact)
//
// Correct them in the screens before they are edited again.
//
//   node scripts/checkDates.js
//   node scripts/checkDates.js --uri-file .env.atlas --db ngo_system
//
// Changes nothing.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript } = require("../utils/scriptConnection");

const { today, day } = require("../models/plugins/dateRules");


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name} (read-only), today ${today()}`);

    const live = (name, extra = {}) => db.collection(name).find({ isDeleted: { $ne: true }, ...extra }).toArray();
    const byId = (rows) => new Map(rows.map(row => [String(row._id), row]));

    const programs = byId(await live("programs"));
    const projects = byId(await live("projects"));
    const runs = byId(await live("activityruns"));
    const people = byId(await db.collection("beneficiaries").find({}).project({ firstName: 1, lastName: 1, beneficiaryNumber: 1, dateOfBirth: 1 }).toArray());
    const enterprises = byId(await live("enterprises"));

    const problems = [];
    const add = (kind, code, text) => problems.push(`${kind.padEnd(20)} ${String(code || "").padEnd(28)} ${text}`);
    const order = (kind, row, code, a, b) => {
        if (row[a] && row[b] && day(row[b]) < day(row[a])) add(kind, row[code], `${b} ${day(row[b])} is before ${a} ${day(row[a])}`);
    };
    const inside = (kind, row, code, fields, parent, parentName) => {
        if (!parent?.startDate) return;
        const start = day(parent.startDate);
        const end = parent.endDate ? day(parent.endDate) : null;
        for (const field of fields) {
            const value = day(row[field]);
            if (value && (value < start || (end && value > end))) add(kind, row[code], `${field} ${value} is outside ${parentName} (${start} to ${end || "open"})`);
        }
    };
    const notFuture = (kind, row, code, field, when = true) => {
        if (when && row[field] && day(row[field]) > today()) add(kind, row[code], `${field} ${day(row[field])} is in the future`);
    };

    for (const program of programs.values()) order("Program", program, "programCode", "startDate", "endDate");

    for (const project of projects.values()) {
        order("Project", project, "projectCode", "startDate", "endDate");
        const program = programs.get(String(project.program));
        inside("Project", project, "projectCode", ["startDate", "endDate"], program, `program ${program?.programCode}`);
    }

    for (const activity of await live("activities")) {
        const project = projects.get(String(activity.project));
        inside("Activity", activity, "activityCode", ["activityDate"], project, `project ${project?.projectCode}`);
    }

    for (const run of runs.values()) {
        order("Activity run", run, "runCode", "startDate", "endDate");
        const project = projects.get(String(run.project));
        inside("Activity run", run, "runCode", ["startDate", "endDate"], project, `project ${project?.projectCode}`);
    }

    for (const tor of await live("termsofreferences")) {
        order("TOR", tor, "torNumber", "startDate", "endDate");
        const project = projects.get(String(tor.project));
        inside("TOR", tor, "torNumber", ["startDate", "endDate"], project, `project ${project?.projectCode}`);
    }

    for (const delivery of await live("servicedeliveries")) {
        const project = projects.get(String(delivery.project));
        inside("Service delivery", delivery, "deliveryNumber", ["deliveryDate"], project, `project ${project?.projectCode}`);
        notFuture("Service delivery", delivery, "deliveryNumber", "deliveryDate", delivery.status === "Delivered");
    }

    for (const session of await live("attendances")) {
        const project = projects.get(String(session.project));
        inside("Attendance session", session, "sessionTitle", ["sessionDate"], project, `project ${project?.projectCode}`);
        const run = runs.get(String(session.activityRun));
        inside("Attendance session", session, "sessionTitle", ["sessionDate"], run, `activity run ${run?.runCode}`);
    }

    for (const record of await db.collection("attendancerecords").find({}).toArray()) {
        order("Attendance record", record, "_id", "checkInTime", "checkOutTime");
    }

    for (const enrollment of await live("enrollments")) {
        order("Enrollment", enrollment, "_id", "enrollmentDate", "completionDate");
        const program = programs.get(String(enrollment.program));
        inside("Enrollment", enrollment, "_id", ["enrollmentDate"], program, `program ${program?.programCode}`);
        const person = people.get(String(enrollment.beneficiary));
        if (person?.dateOfBirth && enrollment.enrollmentDate && day(enrollment.enrollmentDate) < day(person.dateOfBirth)) {
            add("Enrollment", enrollment.enrollmentCode, `enrolled ${day(enrollment.enrollmentDate)}, before ${person.beneficiaryNumber || "the person"} was born (${day(person.dateOfBirth)})`);
        }
    }

    for (const enterprise of enterprises.values()) order("Enterprise", enterprise, "enterpriseNumber", "startDate", "endDate");

    for (const member of await live("enterprisemembers")) {
        order("Enterprise member", member, "_id", "joinedDate", "leftDate");
        const enterprise = enterprises.get(String(member.enterprise));
        inside("Enterprise member", member, "_id", ["joinedDate", "leftDate"], enterprise, `enterprise ${enterprise?.enterpriseCode}`);
    }

    for (const person of people.values()) {
        notFuture("Beneficiary", person, "beneficiaryNumber", "dateOfBirth");
        if (person.dateOfBirth && day(person.dateOfBirth) < "1900-01-01") add("Beneficiary", person.beneficiaryNumber, `date of birth ${day(person.dateOfBirth)} is before 1900`);
    }

    for (const donation of await live("donations")) notFuture("Donation", donation, "donationCode", "donationDate", donation.status === "Received");
    for (const expense of await live("expenses")) notFuture("Expense", expense, "expenseCode", "expenseDate");
    for (const donor of await live("donors")) {
        notFuture("Donor", donor, "name", "donorSince");
        notFuture("Donor", donor, "name", "lastContactDate");
    }

    console.log(problems.length ? `\n${problems.length} date problem(s):\n${problems.join("\n")}` : "\nAll dates follow the rules.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
