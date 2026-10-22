// =====================================================
// UPDATE ONE LIMIT OF A PLAN
// =====================================================
//
// Plans are created from config/defaultPlans.js only when
// they do not exist yet, and each subscription keeps a copy
// of its plan (planSnapshot) that the limits are checked
// against. So a changed limit must be written to both:
//
//   node scripts/updatePlanLimit.js --plan FREE --limit users --value 5 --dry-run
//   node scripts/updatePlanLimit.js --plan FREE --limit users --value 5
//
// Live database: add --uri-file .env.atlas --db ngo_system
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");


const arg = (name) => {
    const index = process.argv.indexOf(`--${name}`);
    return index > -1 ? process.argv[index + 1] : undefined;
};

const DRY_RUN = process.argv.includes("--dry-run");
const PLAN = String(arg("plan") || "").toUpperCase();
const LIMIT = arg("limit");
const VALUE = Number(arg("value"));


const main = async () => {

    if (!PLAN || !LIMIT || !Number.isFinite(VALUE)) {
        throw new Error("Usage: --plan FREE --limit users --value 5 [--dry-run]");
    }

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    const plan = await db.collection("plans").findOne({ code: PLAN });

    if (!plan) throw new Error(`Plan ${PLAN} not found.`);

    if (!(LIMIT in (plan.limits || {}))) {
        throw new Error(`Plan ${PLAN} has no limit "${LIMIT}" (has: ${Object.keys(plan.limits || {}).join(", ")}).`);
    }

    console.log(`Plan ${PLAN}: ${LIMIT} ${plan.limits[LIMIT]} -> ${VALUE}`);

    const subscriptions =
        await db.collection("subscriptions").find({
            $or: [{ plan: plan._id }, { "planSnapshot.code": PLAN }]
        }).toArray();

    console.log(`${subscriptions.length} subscription(s) on ${PLAN} get the new limit.`);

    if (!DRY_RUN) {
        await db.collection("plans").updateOne(
            { _id: plan._id },
            { $set: { [`limits.${LIMIT}`]: VALUE, updatedAt: new Date() } }
        );
        if (subscriptions.length) {
            await db.collection("subscriptions").updateMany(
                { _id: { $in: subscriptions.map(item => item._id) } },
                { $set: { [`planSnapshot.limits.${LIMIT}`]: VALUE, updatedAt: new Date() } }
            );
        }
    }

    console.log(DRY_RUN ? "Dry run: nothing changed." : "Done.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
