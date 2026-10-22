// =====================================================
// CLEAN UP DEFAULT SERVICE DELIVERY LOOKUPS
// =====================================================
//
// For organizations created before the cleanup:
//
// 1. Units: the duplicate default units are hidden
//    (active = false), not deleted, so old deliveries that
//    use them stay valid:
//      Amount, Birr, Money, Cash -> ETB
//      Pieces -> Piece, Kilogram -> Kg, Litre -> Liter
//    Every service type that allowed a duplicate now also
//    allows its replacement.
//
// 2. Service types: trainings and awareness sessions become
//    PARTICIPATION (each beneficiary takes part in the whole
//    delivered quantity) instead of CONSUMPTION.
//
// Only system-default lookups are changed; units or types an
// organization created itself are left alone.
//
//   node scripts/cleanupDefaultLookups.js --dry-run  (only report)
//   node scripts/cleanupDefaultLookups.js            (apply)
//
// Live database:
//   node scripts/cleanupDefaultLookups.js --uri-file .env.atlas --db ngo_system --dry-run
//
// Safe to re-run.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const {
    connectForScript
} = require("../utils/scriptConnection");


const DRY_RUN = process.argv.includes("--dry-run");

// legacy unit code -> unit code that replaces it
const REPLACED_BY = {
    AMOUNT: "ETB",
    BIRR: "ETB",
    MONEY: "ETB",
    CASH: "ETB",
    PCS: "PIECE",
    KILOGRAM: "KG",
    LITRE: "LITER"
};

const PARTICIPATION_TYPES = [
    "Health Awareness Session",
    "Livelihood Training",
    "Vocational Training",
    "Business Skills Training",
    "Youth Skills Training"
];


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;
    const lookups = db.collection("lookups");

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    const organizations =
        await db.collection("organizations").find({}, { projection: { name: 1 } }).toArray();

    for (const organization of organizations) {

        console.log(`\n${organization.name}`);

        const units =
            await lookups.find({ organization: organization._id, module: "ServiceDelivery", category: "Unit" }).toArray();

        const byCode = new Map(units.map(unit => [String(unit.code || "").toUpperCase(), unit]));

        for (const [legacyCode, keepCode] of Object.entries(REPLACED_BY)) {

            const legacy = byCode.get(legacyCode);
            const keep = byCode.get(keepCode);

            if (!legacy || legacy.isSystemDefault === false) continue;
            if (!keep) {
                console.log(`  unit ${legacy.value}: kept (no ${keepCode} unit to replace it)`);
                continue;
            }

            const types =
                await lookups.countDocuments({
                    organization: organization._id, category: "ServiceType", allowedUnits: legacy._id
                });

            console.log(`  unit ${legacy.value} -> ${keep.value}: ${legacy.active === false ? "already hidden" : "hide"}; ${types} service type(s) also get ${keep.value}`);

            if (!DRY_RUN) {
                await lookups.updateMany(
                    { organization: organization._id, category: "ServiceType", allowedUnits: legacy._id },
                    { $addToSet: { allowedUnits: keep._id } }
                );
                await lookups.updateOne({ _id: legacy._id }, { $set: { active: false, updatedAt: new Date() } });
            }

        }

        const types =
            await lookups.find({
                organization: organization._id,
                module: "ServiceDelivery",
                category: "ServiceType",
                value: { $in: PARTICIPATION_TYPES },
                allocationBehavior: { $ne: "PARTICIPATION" }
            }).toArray();

        for (const type of types) {
            console.log(`  service type ${type.value}: ${type.allocationBehavior || "CONSUMPTION"} -> PARTICIPATION`);
        }

        if (!DRY_RUN && types.length) {
            await lookups.updateMany(
                { _id: { $in: types.map(type => type._id) } },
                { $set: { allocationBehavior: "PARTICIPATION", updatedAt: new Date() } }
            );
        }

    }

    console.log(DRY_RUN ? "\nDry run: nothing changed." : "\nDone.");

};


main()
    .catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
