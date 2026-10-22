// =====================================================
// REMOVE THE OLD TYPED BUDGET FIELDS
// =====================================================
//
// Programs had a hand-typed "budget" and projects an
// "approvedBudget". The Budgets module is now the only
// source of budget numbers, so these old values are removed
// (each program / project shows its budget from Budgets).
//
//   node scripts/removeOldBudgetFields.js            (apply)
//   node scripts/removeOldBudgetFields.js --dry-run  (only report)
//
// Uses MONGO_URI from .env. Live database:
//   node scripts/removeOldBudgetFields.js --uri-file .env.atlas --db ngo_system --dry-run
//
// Safe to re-run. Take a backup first (scripts/backupDatabase.js).
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");


const DRY_RUN = process.argv.includes("--dry-run");


const clean = async (collectionName, field, codeField) => {

    const collection = mongoose.connection.collection(collectionName);

    const filter = { [field]: { $exists: true } };

    const documents =
        await collection
            .find(filter, { projection: { [codeField]: 1, name: 1, [field]: 1 } })
            .toArray();

    console.log(`\n${collectionName}.${field}: ${documents.length} record(s)`);

    for (const document of documents) {
        console.log(`  ${document[codeField] || document._id}  ${document.name || ""}  (was ${document[field]})`);
    }

    if (!DRY_RUN && documents.length) {
        const result = await collection.updateMany(filter, { $unset: { [field]: "" } });
        console.log(`  removed from ${result.modifiedCount} record(s)`);
    }

};


const main = async () => {

    await connectForScript();

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    await clean("programs", "budget", "programCode");
    await clean("projects", "approvedBudget", "projectCode");

    console.log(DRY_RUN ? "\nDry run: nothing changed." : "\nDone.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
