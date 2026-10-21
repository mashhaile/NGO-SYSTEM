// =====================================================
// SEED DEFAULT LOOKUPS FOR EXISTING ORGANIZATIONS
// =====================================================
//
// New organizations get these automatically. Use this for
// organizations created before that (or to repair one).
//
//   node scripts/seedDefaultLookups.js            (apply)
//   node scripts/seedDefaultLookups.js --dry-run  (only report)
//
// Uses MONGO_URI from .env (or the environment).
//
// Safe to re-run: only EMPTY categories are filled, so an
// organization's own values are never changed or re-added.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const Organization = require("../models/organization");
const Lookup = require("../models/Lookup");

const {
    initializeOrganization
} = require("../initializers/organizationInitializer");

const {
    DEFAULT_LOOKUPS
} = require("../config/defaultLookups");


const DRY_RUN = process.argv.includes("--dry-run");


const emptyCategories = async (organizationId) => {

    const wanted = [
        ...Object.entries(DEFAULT_LOOKUPS).flatMap(([module, categories]) =>
            Object.keys(categories).map(category => [module, category])
        ),
        ["ServiceDelivery", "Unit"],
        ["ServiceDelivery", "ServiceType"]
    ];

    const empty = [];

    for (const [module, category] of wanted) {
        if (!(await Lookup.exists({ organization: organizationId, module, category }))) {
            empty.push(`${module}/${category}`);
        }
    }

    return empty;

};


const main = async () => {

    if (!process.env.MONGO_URI) {
        throw new Error("MONGO_URI is not set.");
    }

    await mongoose.connect(process.env.MONGO_URI);

    console.log(`Database: ${mongoose.connection.name}${DRY_RUN ? " (dry run)" : ""}`);

    const organizations =
        await Organization.find({ isDeleted: { $ne: true } })
            .select("_id name")
            .lean();

    for (const organization of organizations) {

        const empty =
            await emptyCategories(organization._id);

        if (!empty.length) {
            console.log(`- ${organization.name}: complete, nothing to add`);
            continue;
        }

        console.log(`- ${organization.name}: empty -> ${empty.join(", ")}`);

        if (DRY_RUN) {
            continue;
        }

        await initializeOrganization(organization._id, null);

        const before =
            empty.length;

        const after =
            (await emptyCategories(organization._id)).length;

        console.log(`  filled ${before - after} of ${before} categories`);

    }

    await mongoose.disconnect();

};


main().catch(async (error) => {
    console.error(error.message);
    await mongoose.disconnect().catch(() => {});
    process.exit(1);
});
