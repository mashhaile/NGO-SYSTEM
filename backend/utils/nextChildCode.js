// =====================================================
// NEXT CODE UNDER A PARENT
// =====================================================
//
// Codes numbered within a parent: PRG-000001-PRJ-003 (a
// project of a program), ...-ACT-002 (an activity of a
// project), ...-RUN-001 (a run of an activity).
//
// "Count + 1" gave two records created at the same moment
// the same code (and reused a deleted record's number). An
// atomic counter per parent never hands out a number twice;
// a code already taken (records made before the counter)
// is skipped.
//
// =====================================================

const Counter = require("../models/Counter");


const nextChildCode = async ({ organizationId, key, prefix, isTaken, digits = 3 }) => {

    for (let attempt = 0; attempt < 1000; attempt++) {

        let counter;
        try {
            counter = await Counter.findOneAndUpdate(
                { organization: organizationId, module: key },
                { $inc: { sequence: 1 } },
                { upsert: true, returnDocument: "after" }
            );
        }
        catch (error) {
            // two first codes at once: one creates the counter, the other retries
            if (error?.code === 11000) continue;
            throw error;
        }

        const code = `${prefix}-${String(counter.sequence).padStart(digits, "0")}`;

        if (!isTaken || !(await isTaken(code))) return code;

    }

    throw new Error(`Could not find a free code for ${prefix}.`);

};


module.exports = nextChildCode;
