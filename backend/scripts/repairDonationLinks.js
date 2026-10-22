// =====================================================
// FILL IN MISSING DONATION PARENTS
// =====================================================
//
// A donation linked to an activity run / activity / project
// now also stores the activity, project and program above
// it (done on save). This fills them in for donations saved
// before, so program reports count them.
//
//   node scripts/repairDonationLinks.js            (apply)
//   node scripts/repairDonationLinks.js --dry-run  (only report)
//
// Live database:
//   node scripts/repairDonationLinks.js --uri-file .env.atlas --db ngo_system --dry-run
//
// Safe to re-run: only empty links are filled.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");


const DRY_RUN = process.argv.includes("--dry-run");


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    const donations =
        await db.collection("donations")
            .find({ isDeleted: { $ne: true }, $or: [{ program: null }, { project: null }, { activity: null }] })
            .toArray();

    let changed = 0;

    for (const donation of donations) {

        const set = {};
        let activity = donation.activity;
        let project = donation.project;

        if (!activity && donation.activityRun) {
            const run = await db.collection("activityruns").findOne({ _id: donation.activityRun }, { projection: { activity: 1 } });
            if (run?.activity) set.activity = activity = run.activity;
        }

        if (!project && activity) {
            const found = await db.collection("activities").findOne({ _id: activity }, { projection: { project: 1 } });
            if (found?.project) set.project = project = found.project;
        }

        if (!donation.program && project) {
            const found = await db.collection("projects").findOne({ _id: project }, { projection: { program: 1 } });
            if (found?.program) set.program = found.program;
        }

        if (Object.keys(set).length) {
            changed++;
            console.log(`  ${donation.donationCode || donation._id}  ${donation.title}: ${Object.keys(set).join(", ")}`);
            if (!DRY_RUN) {
                await db.collection("donations").updateOne({ _id: donation._id }, { $set: set });
            }
        }

    }

    console.log(`\n${changed} donation(s) ${DRY_RUN ? "would be" : ""} updated.`);

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
