// =====================================================
// BACKFILL ATTENDANCE LOCATIONS
// =====================================================
//
// Fills the location snapshot on attendance records
// saved before location snapshots existed, using the
// same rules as saving an attendance sheet
// (see createAttendanceLocationResolver).
//
// Only records without a region code are touched.
//
// Usage (from backend/):
//
//     node scripts/backfillAttendanceLocations.js          (dry run)
//     node scripts/backfillAttendanceLocations.js --apply  (write)
//
// =====================================================

require("dotenv").config();

const mongoose = require("mongoose");

require("../models/Beneficiary");
require("../models/ActivityRun");

const AttendanceRecord =
    require("../models/AttendanceRecord");

const {
    createAttendanceLocationResolver
} = require("../services/attendanceService");


const APPLY =
    process.argv.includes("--apply");


const backfill = async () => {

    await mongoose.connect(
        process.env.MONGO_URI
    );

    console.log(
        APPLY
            ? "Applying attendance location backfill"
            : "Dry run (pass --apply to write)"
    );


    const records =
        await AttendanceRecord.find({
            $or: [
                { location: null },
                { "location.regionCode": { $in: [null, ""] } }
            ]
        })
            .select(
                "organization activityRun participantType beneficiary location"
            )
            .lean();


    // One resolver per organization + activity run.

    const groups =
        new Map();

    records.forEach(record => {

        const key =
            `${record.organization}|${record.activityRun || ""}`;

        if (!groups.has(key)) {
            groups.set(key, []);
        }

        groups.get(key).push(record);

    });


    let updated = 0;
    let unresolved = 0;

    const operations = [];


    for (const groupRecords of groups.values()) {

        const {
            organization,
            activityRun
        } = groupRecords[0];

        const resolveLocation =
            await createAttendanceLocationResolver({
                organizationId:
                    organization,
                activityRunId:
                    activityRun,
                participants:
                    groupRecords
            });


        groupRecords.forEach(record => {

            const location =
                resolveLocation(record);

            if (!location?.regionCode) {
                unresolved++;
                return;
            }

            updated++;

            operations.push({
                updateOne: {
                    filter: {
                        _id: record._id
                    },
                    update: {
                        $set: {
                            location: {
                                ...(record.location || {}),
                                ...location
                            }
                        }
                    }
                }
            });

        });

    }


    if (APPLY && operations.length) {

        await AttendanceRecord.bulkWrite(
            operations
        );

    }


    console.log(
        `Records without location: ${records.length}\n` +
        `${APPLY ? "Updated" : "Would update"}: ${updated}\n` +
        `No location available (beneficiary and activity run have none): ${unresolved}`
    );

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
