// =====================================================
// CHECK PROJECT DATES (read-only)
// =====================================================
//
// Lists activities, activity runs, service deliveries and
// attendance sessions dated outside their project's start
// and end dates (see models/plugins/insideProjectDates.js).
// Correct them in the screens: move the record's date, or
// widen the project's dates.
//
//   node scripts/checkProjectDates.js
//   node scripts/checkProjectDates.js --uri-file .env.atlas --db ngo_system
//
// Changes nothing.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript } = require("../utils/scriptConnection");


const RECORDS = [
    { collection: "activities", code: "activityCode", dates: ["activityDate"], label: "Activities" },
    { collection: "activityruns", code: "runCode", dates: ["startDate", "endDate"], label: "Activity runs" },
    { collection: "servicedeliveries", code: "deliveryNumber", dates: ["deliveryDate"], label: "Service deliveries" },
    { collection: "attendances", code: "sessionTitle", dates: ["sessionDate"], label: "Attendance sessions" }
];

const day = (value) => (value ? new Date(value).toISOString().slice(0, 10) : null);


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name} (read-only)`);

    const projects = new Map(
        (await db.collection("projects").find({ isDeleted: { $ne: true } }).project({ name: 1, projectCode: 1, startDate: 1, endDate: 1 }).toArray())
            .map(project => [String(project._id), project])
    );

    let total = 0;

    for (const record of RECORDS) {

        const rows = await db.collection(record.collection).find({ isDeleted: { $ne: true }, project: { $ne: null } }).toArray();
        const outside = [];

        for (const row of rows) {
            const project = projects.get(String(row.project));
            if (!project?.startDate || !project?.endDate) continue;
            const start = day(project.startDate);
            const end = day(project.endDate);
            const wrong = record.dates.filter(field => row[field] && (day(row[field]) < start || day(row[field]) > end));
            if (wrong.length) {
                outside.push(`  ${row[record.code] || row._id}: ${wrong.map(field => `${field} ${day(row[field])}`).join(", ")}; ${project.projectCode} ${project.name} runs ${start} to ${end}`);
            }
        }

        total += outside.length;
        console.log(`\n${record.label} outside their project's dates: ${outside.length} of ${rows.length}`);
        for (const line of outside) console.log(line);

    }

    console.log(total ? `\n${total} record(s) to correct (they can still be edited; a changed date must be inside the project).` : "\nAll records are inside their project's dates.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
