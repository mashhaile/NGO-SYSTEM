const Lookup = require("../models/Lookup");

const {
    DEFAULT_LOOKUPS,
    DEFAULT_SERVICE_TYPES
} = require("../config/defaultLookups");


// =====================================================
// DEFAULT LOOKUPS FOR AN ORGANIZATION
// =====================================================
//
// Idempotent and safe to run any number of times:
//
// - A category is seeded only while the organization has
//   NO values in it (active or inactive). Once it has any,
//   it belongs to the organization and is left alone, so
//   edits and deletions are never undone.
// - Service Types need their parent Service Category and
//   the standard Units, so they are seeded last and only
//   link to categories / units that exist.
//
// Returns { [module/category]: insertedCount } for logging.
//
// =====================================================

const toCode = (value) =>
    String(value)
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "");


// Inserts, ignoring duplicates (e.g. two requests seeding
// the same organization at once hit the unique index).

const insertIgnoringDuplicates = async (docs) => {

    if (!docs.length) {
        return 0;
    }

    try {
        const result =
            await Lookup.insertMany(docs, { ordered: false });
        return result.length;
    }
    catch (error) {
        if (error.code === 11000 || error.writeErrors) {
            return error.insertedDocs?.length ?? 0;
        }
        throw error;
    }

};


const categoryIsEmpty = async (organizationId, module, category) =>
    !(await Lookup.exists({
        organization: organizationId,
        module,
        category
    }));


const ensureOrganizationDefaultLookups = async (
    organizationId,
    userId = null
) => {

    if (!organizationId) {
        throw new Error("Organization is required.");
    }

    const summary = {};


    // Simple categories

    for (const [module, categories] of Object.entries(DEFAULT_LOOKUPS)) {

        for (const [category, values] of Object.entries(categories)) {

            if (!(await categoryIsEmpty(organizationId, module, category))) {
                continue;
            }

            summary[`${module}/${category}`] =
                await insertIgnoringDuplicates(
                    values.map(value => ({
                        organization: organizationId,
                        module,
                        category,
                        value,
                        code: toCode(value),
                        active: true,
                        createdBy: userId
                    }))
                );

        }

    }


    // Service Types (need categories + units)

    if (await categoryIsEmpty(organizationId, "ServiceDelivery", "ServiceType")) {

        const [categories, units] =
            await Promise.all([
                Lookup.find({
                    organization: organizationId,
                    module: "ServiceDelivery",
                    category: "ServiceCategory"
                }).select("_id value").lean(),
                Lookup.find({
                    organization: organizationId,
                    module: "ServiceDelivery",
                    category: "Unit"
                }).select("_id value").lean()
            ]);

        const byValue = (rows) =>
            new Map(rows.map(row => [row.value.toLowerCase(), row._id]));

        const categoryIds = byValue(categories);
        const unitIds = byValue(units);

        const docs =
            DEFAULT_SERVICE_TYPES
                .filter(type => categoryIds.has(type.category.toLowerCase()))
                .map(type => ({
                    organization: organizationId,
                    module: "ServiceDelivery",
                    category: "ServiceType",
                    value: type.value,
                    code: toCode(type.value),
                    parentLookup: categoryIds.get(type.category.toLowerCase()),
                    allowedUnits: type.units
                        .map(unit => unitIds.get(unit.toLowerCase()))
                        .filter(Boolean),
                    active: true,
                    createdBy: userId
                }));

        summary["ServiceDelivery/ServiceType"] =
            await insertIgnoringDuplicates(docs);

    }

    return summary;

};


module.exports = {
    ensureOrganizationDefaultLookups
};
