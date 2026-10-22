const Counter = require("../models/Counter");

// Next code for a module: PREFIX-000001, PREFIX-000002, ...
//
// isTaken (optional): async (code) => boolean. When the counter
// is behind the records (records created before the counter
// existed, a restored backup, ...), taken codes are skipped
// instead of failing on the unique index.
const generateSequence = async (
    moduleName,
    prefix,
    organizationId,
    isTaken = null
) => {

    for (let attempt = 0; attempt < 1000; attempt++) {

        const counter =
            await Counter.findOneAndUpdate(
                {
                    organization: organizationId,
                    module: moduleName
                },
                {
                    $inc: {
                        sequence: 1
                    }
                },
                {
                    upsert: true,
                    returnDocument: "after"
                }
            );

        const code =
            `${prefix}-${counter.sequence.toString().padStart(6, "0")}`;

        if (!isTaken || !(await isTaken(code))) {
            return code;
        }

    }

    throw new Error(`Could not find a free ${moduleName} code.`);

};

module.exports = generateSequence;
