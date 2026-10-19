// =====================================================
// BACKFILL LOCATION CODES
// =====================================================
//
// Adds official P-codes (regionCode / zoneCode /
// woredaCode) to records saved with free-text
// locations before the official list existed.
//
// Each level is matched top down by name (case and
// spacing insensitive). Matched names are rewritten
// to the official spelling; unmatched names are kept
// as typed and matching stops at that level.
//
// Collections: Beneficiary, Enterprise, Activity,
// ActivityRun.
//
// Usage (from backend/):
//
//     node scripts/backfillLocationCodes.js          (dry run)
//     node scripts/backfillLocationCodes.js --apply  (write)
//
// =====================================================

require("dotenv").config();

const mongoose = require("mongoose");

const {
    createLocationResolver
} = require("../services/locationService");


const MODELS = [
    "Beneficiary",
    "Enterprise",
    "Activity",
    "ActivityRun"
];


const APPLY =
    process.argv.includes("--apply");


const backfill = async () => {

    await mongoose.connect(
        process.env.MONGO_URI
    );

    console.log(
        APPLY
            ? "Applying location code backfill"
            : "Dry run (pass --apply to write)"
    );


    const resolver =
        await createLocationResolver();


    for (const modelName of MODELS) {

        const Model =
            require(`../models/${modelName}`);


        const records =
            await Model.find({
                region: {
                    $nin: [null, ""]
                },
                $or: [
                    { regionCode: { $in: [null, ""] } },
                    { regionCode: { $exists: false } }
                ]
            })
                .select("region zone woreda")
                .lean();


        const operations = [];

        const unmatched = new Map();

        let fullMatches = 0;


        records.forEach(record => {

            const {
                regionArea,
                zoneArea,
                woredaArea
            } = resolver.matchPartial(record);


            if (!regionArea) {

                const key =
                    `region "${record.region}"`;

                unmatched.set(
                    key,
                    (unmatched.get(key) || 0) + 1
                );

                return;

            }


            const update = {
                region: regionArea.name,
                regionCode: regionArea.pcode
            };

            if (zoneArea) {
                update.zone = zoneArea.name;
                update.zoneCode = zoneArea.pcode;
            }
            else if (record.zone) {

                const key =
                    `zone "${record.zone}" in ${regionArea.name}`;

                unmatched.set(
                    key,
                    (unmatched.get(key) || 0) + 1
                );

            }

            if (woredaArea) {
                update.woreda = woredaArea.name;
                update.woredaCode = woredaArea.pcode;
            }

            if (
                woredaArea ||
                (zoneArea && !record.woreda)
            ) {
                fullMatches++;
            }


            operations.push({
                updateOne: {
                    filter: {
                        _id: record._id
                    },
                    update: {
                        $set: update
                    }
                }
            });

        });


        if (APPLY && operations.length) {

            await Model.collection.bulkWrite(
                operations
            );

        }


        console.log(
            `\n${modelName}: ${records.length} without codes, ` +
            `${operations.length} ${APPLY ? "updated" : "would be updated"} ` +
            `(${fullMatches} fully matched)`
        );

        unmatched.forEach((count, key) => {
            console.log(
                `   not in official list: ${key} (${count})`
            );
        });

    }

};


backfill()

    .catch(error => {
        console.error(
            "❌ Backfill failed:",
            error.message
        );
        process.exitCode = 1;
    })

    .finally(() =>
        mongoose.disconnect()
    );
