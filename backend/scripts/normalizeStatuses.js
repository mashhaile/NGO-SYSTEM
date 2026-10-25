// =====================================================
// NORMALIZE STATUSES (one lifecycle for all work)
// =====================================================
//
// Programs, projects (and phases), activities and activity
// runs now share Planned / Active / Suspended / Completed /
// Cancelled (constants/workStatus.js). Older values are
// rewritten:
//
//   project  "Draft"   -> "Planned"
//   activity "Ongoing" -> "Active"
//   enterprise status outside Active / Inactive -> "Active"
//
//   node scripts/normalizeStatuses.js            (dry run: what would change)
//   node scripts/normalizeStatuses.js --apply
//   node scripts/normalizeStatuses.js --uri-file .env.atlas --db ngo_system [--apply]
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript } = require("../utils/scriptConnection");
const { LEGACY_WORK_STATUS } = require("../constants/workStatus");


const APPLY = process.argv.includes("--apply");

const main = async () => {

    await connectForScript();
    const db = mongoose.connection.db;
    console.log(`Database: ${mongoose.connection.name} (${APPLY ? "applying" : "dry run"})`);

    let total = 0;

    for (const collection of ["programs", "projects", "activities", "activityruns"]) {
        for (const [from, to] of Object.entries(LEGACY_WORK_STATUS)) {
            const count = await db.collection(collection).countDocuments({ status: from });
            if (!count) continue;
            total += count;
            console.log(`  ${collection}: ${count} "${from}" -> "${to}"`);
            if (APPLY) await db.collection(collection).updateMany({ status: from }, { $set: { status: to } });
        }
    }

    const oddEnterprises = await db.collection("enterprises").countDocuments({ status: { $nin: ["Active", "Inactive"] } });
    if (oddEnterprises) {
        total += oddEnterprises;
        console.log(`  enterprises: ${oddEnterprises} with another status -> "Active"`);
        if (APPLY) await db.collection("enterprises").updateMany({ status: { $nin: ["Active", "Inactive"] } }, { $set: { status: "Active" } });
    }

    console.log(total ? `\n${total} record(s) ${APPLY ? "updated" : "would be updated (add --apply)"}.` : "\nAll statuses already follow the lifecycle.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
