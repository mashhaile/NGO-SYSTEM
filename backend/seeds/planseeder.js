const mongoose = require("mongoose");
const dotenv = require("dotenv");

const Plan = require("../models/plan");

dotenv.config();


// =====================================================
// SEED PLANS
//
// IMPORTANT:
// All modules are available on ALL plans.
//
// Plans control:
// - User limits
// - Beneficiary limits
// - Other resource limits
// - Feature availability
// - Pricing
//
// Plans DO NOT control module availability.
// =====================================================

// WARNING: this RESETS every default plan (price, limits,
// features) to config/defaultPlans.js, overwriting edits
// made by the super admin. Missing plans are created
// automatically at server startup, so this is only needed
// to deliberately reset plans.

async function seedPlans() {

    try {

        await mongoose.connect(
            process.env.MONGO_URI
        );

        console.log("MongoDB Connected");


        const plans =
            require("../config/defaultPlans");


        // =====================================================
        // UPSERT PLANS
        // =====================================================

        const operations = plans.map(

            (plan) => ({

                updateOne: {

                    filter: {

                        code: plan.code

                    },

                    update: {

                        $set: plan

                    },

                    upsert: true

                }

            })

        );


        await Plan.bulkWrite(

            operations

        );


        console.log(
            "✅ Plans seeded successfully."
        );


        // =====================================================
        // DISPLAY SEEDED PLANS
        // =====================================================

        const seededPlans =

            await Plan.find({})

                .sort({

                    sortOrder: 1

                })

                .select(

                    "name code price currency billingCycle limits.users limits.beneficiaries isActive isPublic sortOrder"

                );


        console.table(

            seededPlans.map(

                (plan) => ({

                    name:
                        plan.name,

                    code:
                        plan.code,

                    price:
                        plan.price,

                    currency:
                        plan.currency,

                    billingCycle:
                        plan.billingCycle,

                    users:
                        plan.limits.users,

                    beneficiaries:
                        plan.limits.beneficiaries,

                    active:
                        plan.isActive,

                    public:
                        plan.isPublic,

                    order:
                        plan.sortOrder

                })

            )

        );

    }


    catch (error) {

        console.error(
            "❌ Error seeding plans:"
        );

        console.error(
            error
        );

        process.exitCode = 1;

    }


    finally {

        await mongoose.connection.close();

        console.log(
            "MongoDB connection closed."
        );

    }

}


seedPlans();