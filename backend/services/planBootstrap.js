const Plan = require("../models/plan");

const DEFAULT_PLANS = require("../config/defaultPlans");


// =====================================================
// ENSURE DEFAULT PLANS (runs at server startup)
// =====================================================
//
// Creates any default plan that does not exist yet (by
// code). Existing plans are NEVER changed, so prices and
// limits edited by the super admin survive restarts and
// deploys. Sign-up needs the Free plan, so a fresh
// database works without running seeds/planseeder.js.
//
// =====================================================

const ensureDefaultPlans = async () => {

    const result =
        await Plan.bulkWrite(
            DEFAULT_PLANS.map(plan => ({
                updateOne: {
                    filter: { code: plan.code },
                    update: { $setOnInsert: plan },
                    upsert: true
                }
            })),
            { ordered: false }
        );

    const created =
        result.upsertedCount || 0;

    if (created) {
        console.log(`Plans: created ${created} missing default plan(s).`);
    }

    return created;

};


module.exports = {
    ensureDefaultPlans
};
