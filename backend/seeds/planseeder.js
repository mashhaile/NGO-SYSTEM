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

async function seedPlans() {

    try {

        await mongoose.connect(
            process.env.MONGO_URI
        );

        console.log("MongoDB Connected");


        const plans = [

            // =================================================
            // FREE
            // =================================================

            {

                name: "Free",

                code: "FREE",

                description:
                    "Free plan with access to all platform modules for small organizations and evaluation.",

                price: 0,

                currency: "USD",

                billingCycle: "monthly",


                limits: {

                    users: 2,

                    beneficiaries: 100,

                    donors: 100,

                    donations: 100,

                    programs: 10,

                    projects: 10,

                    activities: 100,

                    activityRuns: 250,

                    enrollments: 100,

                    serviceDeliveries: 100,

                    attendanceRecords: 250,

                    customFields: 10,

                    storageMB: 500

                },


                features: {

                    dashboard: true,

                    reports: true,

                    exports: {

                        json: true,

                        excel: false,

                        csv: false,

                        pdf: false

                    },

                    apiAccess: false,

                    customFields: false,

                    notifications: true,

                    aiReports: false,

                    scheduledReports: false,

                    automation: false

                },


                trialDays: 30,

                isActive: true,

                isPublic: true,

                sortOrder: 1

            },


            // =================================================
            // STARTER
            // =================================================

            {

                name: "Starter",

                code: "STARTER",

                description:
                    "Starter plan for growing nonprofit organizations with access to all platform modules.",

                price: 19,

                currency: "USD",

                billingCycle: "monthly",


                limits: {

                    users: 10,

                    beneficiaries: 2000,

                    donors: 2000,

                    donations: 2000,

                    programs: 25,

                    projects: 25,

                    activities: 500,

                    activityRuns: 2000,

                    enrollments: 2000,

                    serviceDeliveries: 2000,

                    attendanceRecords: 5000,

                    customFields: 50,

                    storageMB: 5000

                },


                features: {

                    dashboard: true,

                    reports: true,

                    exports: {

                        json: true,

                        excel: true,

                        csv: true,

                        pdf: false

                    },

                    apiAccess: false,

                    customFields: true,

                    notifications: true,

                    aiReports: false,

                    scheduledReports: false,

                    automation: false

                },


                trialDays: 14,

                isActive: true,

                isPublic: true,

                sortOrder: 2

            },


            // =================================================
            // PROFESSIONAL
            // =================================================

            {

                name: "Professional",

                code: "PRO",

                description:
                    "Professional plan for established nonprofit organizations with higher resource limits and advanced features.",

                price: 49,

                currency: "USD",

                billingCycle: "monthly",


                limits: {

                    users: 100,

                    beneficiaries: 100000,

                    donors: 100000,

                    donations: 100000,

                    programs: 1000,

                    projects: 1000,

                    activities: 10000,

                    activityRuns: 50000,

                    enrollments: 100000,

                    serviceDeliveries: 100000,

                    attendanceRecords: 250000,

                    customFields: 500,

                    storageMB: 50000

                },


                features: {

                    dashboard: true,

                    reports: true,

                    exports: {

                        json: true,

                        excel: true,

                        csv: true,

                        pdf: true

                    },

                    apiAccess: true,

                    customFields: true,

                    notifications: true,

                    aiReports: false,

                    scheduledReports: true,

                    automation: true

                },


                trialDays: 14,

                isActive: true,

                isPublic: true,

                sortOrder: 3

            },


            // =================================================
            // ENTERPRISE
            // =================================================

            {

                name: "Enterprise",

                code: "ENTERPRISE",

                description:
                    "Enterprise plan with unlimited resources and complete platform access.",

                price: 0,

                currency: "USD",

                billingCycle: "yearly",


                limits: {

                    users: -1,

                    beneficiaries: -1,

                    donors: -1,

                    donations: -1,

                    programs: -1,

                    projects: -1,

                    activities: -1,

                    activityRuns: -1,

                    enrollments: -1,

                    serviceDeliveries: -1,

                    attendanceRecords: -1,

                    customFields: -1,

                    storageMB: -1

                },


                features: {

                    dashboard: true,

                    reports: true,

                    exports: {

                        json: true,

                        excel: true,

                        csv: true,

                        pdf: true

                    },

                    apiAccess: true,

                    customFields: true,

                    notifications: true,

                    aiReports: true,

                    scheduledReports: true,

                    automation: true

                },


                trialDays: 30,

                isActive: true,

                isPublic: true,

                sortOrder: 4

            }

        ];


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