const mongoose = require("mongoose");

const Lookup = require("../models/Lookup");

const {
    normalizeModule,
    getSystemLookupCategories,
    getSystemLookupFieldByCategory,
    getSystemLookupModules
} = require("../config/systemLookupFields");


// =====================================================
// HELPERS
// =====================================================

const normalizeString = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }

    return String(value).trim();

};


const normalizeCategory = (value) => {

    return normalizeString(value);

};


const normalizeValue = (value) => {

    return normalizeString(value);

};


const normalizeValueKey = (value) => {

    return normalizeString(value)
        .toLowerCase();

};


const normalizeCode = (value) => {

    return normalizeString(value)
        .toUpperCase();

};


const normalizeCodeKey = (value) => {

    return normalizeCode(value);

};


const normalizeBoolean = (value) => {

    if (
        value === true ||
        value === "true" ||
        value === 1 ||
        value === "1"
    ) {

        return true;

    }

    if (
        value === false ||
        value === "false" ||
        value === 0 ||
        value === "0"
    ) {

        return false;

    }

    return Boolean(value);

};


// =====================================================
// NORMALIZE ALLOCATION BEHAVIOR
// =====================================================
//
// Used only by:
//
// module: ServiceDelivery
// category: ServiceType
//
// Allowed values:
//
// CONSUMPTION
// PARTICIPATION
//
// If no value is supplied, the system defaults to
// CONSUMPTION for backward compatibility.
//
// =====================================================

const normalizeAllocationBehavior = (
    value,
    defaultValue = "CONSUMPTION"
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return defaultValue;

    }

    const normalized =
        String(value)
            .trim()
            .toUpperCase();


    if (
        normalized === "CONSUMPTION"
    ) {

        return "CONSUMPTION";

    }


    if (
        normalized === "PARTICIPATION"
    ) {

        return "PARTICIPATION";

    }


    throw new Error(
        "Service Type allocation behavior must be either CONSUMPTION or PARTICIPATION."
    );

};


const normalizeOrganizationId = (organizationId) => {

    if (!organizationId) {

        throw new Error(
            "Organization is required"
        );

    }

    if (
        organizationId instanceof mongoose.Types.ObjectId
    ) {

        return organizationId;

    }

    if (
        mongoose.Types.ObjectId.isValid(
            organizationId
        )
    ) {

        return new mongoose.Types.ObjectId(
            organizationId
        );

    }

    throw new Error(
        "Invalid organization ID"
    );

};


const escapeRegex = (value) => {

    return String(value).replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );

};


// =====================================================
// NORMALIZE ALLOWED UNITS
// =====================================================

const normalizeAllowedUnits = (value) => {

    if (
        value === undefined ||
        value === null
    ) {

        return [];

    }

    if (
        !Array.isArray(value)
    ) {

        throw new Error(
            "Allowed Units must be an array."
        );

    }

    const result = [];

    const seen =
        new Set();

    for (
        const item
        of value
    ) {

        let id =
            item;

        if (
            item &&
            typeof item === "object"
        ) {

            id =
                item._id ||
                item.id ||
                item.value ||
                null;

        }

        if (!id) {

            continue;

        }

        const stringId =
            String(id).trim();

        if (!mongoose.Types.ObjectId.isValid(stringId)) {

            throw new Error(
                "One or more Allowed Units are invalid."
            );

        }

        if (
            seen.has(stringId)
        ) {

            continue;

        }

        seen.add(
            stringId
        );

        result.push(
            new mongoose.Types.ObjectId(
                stringId
            )
        );

    }

    return result;

};


// =====================================================
// MODULE ALIASES
// =====================================================

const getModuleAliases = (module) => {

    const canonicalModule =
        normalizeModule(module);

    if (!canonicalModule) {

        return [];

    }

    const aliases = [
        canonicalModule
    ];

    const lower =
        canonicalModule.toLowerCase();

    switch (lower) {

        case "beneficiary":

            aliases.push(
                "beneficiary",
                "beneficiaries",
                "Beneficiaries"
            );

            break;

        case "enterprise":

            aliases.push(
                "enterprise",
                "enterprises",
                "Enterprises"
            );

            break;

        case "donor":

            aliases.push(
                "donor",
                "donors",
                "Donors"
            );

            break;

        case "program":

            aliases.push(
                "program",
                "programs",
                "Programs"
            );

            break;

        case "user":

            aliases.push(
                "user",
                "users",
                "Users"
            );

            break;

        case "servicedelivery":

            aliases.push(
                "servicedelivery",
                "service-delivery",
                "service-deliveries"
            );

            break;

        case "enterprisemember":

            aliases.push(
                "enterprisemember",
                "enterprisemembers",
                "enterprise-member",
                "enterprise-members"
            );

            break;

    }

    return Array.from(
        new Set(
            aliases
        )
    );

};


// =====================================================
// RESOLVE SYSTEM LOOKUP FIELD
// =====================================================

const resolveSystemLookupField = (
    module,
    category
) => {

    const normalizedModule =
        normalizeModule(module);

    const normalizedCategory =
        normalizeCategory(category);

    if (!normalizedModule) {

        throw new Error(
            "Module is required"
        );

    }

    if (!normalizedCategory) {

        throw new Error(
            "Lookup category is required"
        );

    }

    const supportedModules =
        getSystemLookupModules();

    const moduleExists =
        supportedModules.some(
            item =>
                item === normalizedModule
        );

    if (!moduleExists) {

        throw new Error(
            `Module "${normalizedModule}" is not configured for system lookups`
        );

    }

    const field =
        getSystemLookupFieldByCategory(
            normalizedModule,
            normalizedCategory
        );

    if (!field) {

        throw new Error(
            `Lookup category "${normalizedCategory}" is not allowed for module "${normalizedModule}"`
        );

    }

    return {

        module:
            normalizedModule,

        field

    };

};


const validateSystemLookupCategory = (
    module,
    category
) => {

    return resolveSystemLookupField(
        module,
        category
    );

};


// =====================================================
// VALIDATE PARENT LOOKUP
// =====================================================
//
// ServiceCategory
//      ↑
// ServiceType
//
// ServiceType.parentLookup ALWAYS references
// ServiceDelivery / ServiceCategory.
//
// =====================================================

const validateParentLookup = async ({
    parentLookup,
    organization,
    module,
    category
}) => {

    // -------------------------------------------------
    // ServiceCategory MUST NOT have a parent
    // -------------------------------------------------

    if (
        category === "ServiceCategory"
    ) {

        if (parentLookup) {

            throw new Error(
                "Service Category cannot have a parent."
            );

        }

        return null;

    }


    // -------------------------------------------------
    // ServiceType MUST have ServiceCategory parent
    // -------------------------------------------------

    if (
        category !== "ServiceType"
    ) {

        return null;

    }


    if (!parentLookup) {

        throw new Error(
            "Service Type must belong to a Service Category."
        );

    }


    if (
        !mongoose.Types.ObjectId.isValid(
            parentLookup
        )
    ) {

        throw new Error(
            "Invalid Service Category."
        );

    }


    const parent =
        await Lookup.findOne({

            _id:
                parentLookup,

            organization:
                organization,

            module:
                module,

            category:
                "ServiceCategory",

            active:
                true

        });


    if (!parent) {

        throw new Error(
            "Selected Service Category was not found."
        );

    }


    return parent._id;

};


// =====================================================
// VALIDATE ALLOWED UNITS
// =====================================================
//
// ServiceType
//      ↓
// allowedUnits[]
//      ↓
// ServiceDelivery / Unit
//
// All Units must:
// - belong to same organization
// - be active
// - be ServiceDelivery / Unit
// - exist in the database
//
// =====================================================

const validateAllowedUnits = async ({
    allowedUnits,
    organization,
    module,
    category
}) => {

    if (
        category !== "ServiceType"
    ) {

        return [];

    }


    const normalizedAllowedUnits =
        normalizeAllowedUnits(
            allowedUnits
        );


    if (
        normalizedAllowedUnits.length === 0
    ) {

        throw new Error(
            "Service Type must have at least one allowed unit."
        );

    }


    const uniqueIds =
        new Set(

            normalizedAllowedUnits.map(
                unit =>
                    String(unit)
            )

        );


    if (
        uniqueIds.size !==
        normalizedAllowedUnits.length
    ) {

        throw new Error(
            "Service Type allowed units must be unique."
        );

    }


    const units =
        await Lookup.find({

            _id: {

                $in:
                    normalizedAllowedUnits

            },

            organization:
                organization,

            module:
                module,

            category:
                "Unit",

            active:
                true

        })
        .select(
            "_id value code semanticType active module category"
        )
        .lean();


    if (
        units.length !==
        normalizedAllowedUnits.length
    ) {

        const foundIds =
            new Set(

                units.map(
                    unit =>
                        String(unit._id)
                )

            );


        const missing =
            normalizedAllowedUnits.filter(

                unit =>
                    !foundIds.has(
                        String(unit)
                    )

            );


        const missingText =
            missing
                .map(
                    unit =>
                        String(unit)
                )
                .join(", ");


        throw new Error(
            `One or more selected Allowed Units were not found, are inactive, or do not belong to ServiceDelivery/Unit: ${missingText}`
        );

    }


    for (
        const unit
        of units
    ) {

        if (
            unit.module !==
            "ServiceDelivery"
        ) {

            throw new Error(
                `Allowed Unit "${unit.value}" does not belong to ServiceDelivery.`
            );

        }


        if (
            unit.category !==
            "Unit"
        ) {

            throw new Error(
                `Allowed Unit "${unit.value}" is not a Service Delivery Unit.`
            );

        }

    }


    const orderedIds = [];

    for (
        const requestedUnit
        of normalizedAllowedUnits
    ) {

        const found =
            units.find(

                unit =>
                    String(unit._id) ===
                    String(requestedUnit)

            );


        if (found) {

            orderedIds.push(
                found._id
            );

        }

    }


    return orderedIds;

};


// =====================================================
// FIND EXISTING LOOKUP
// =====================================================

const findExistingLookup = async (
    organizationId,
    module,
    category,
    value,
    excludeId = null
) => {

    const moduleAliases =
        getModuleAliases(module);

    const filter = {

        organization:
            organizationId,

        module: {

            $in:
                moduleAliases

        },

        category:
            category,

        value: {

            $regex:
                `^${escapeRegex(value)}$`,

            $options:
                "i"

        }

    };

    if (excludeId) {

        filter._id = {

            $ne:
                excludeId

        };

    }

    return Lookup.findOne(
        filter
    )
        .lean();

};


// =====================================================
// FIND EXISTING LOOKUP BY CODE
// =====================================================

const findExistingLookupByCode = async (
    organizationId,
    module,
    category,
    code,
    excludeId = null
) => {

    if (!code) {

        return null;

    }

    const moduleAliases =
        getModuleAliases(module);

    const filter = {

        organization:
            organizationId,

        module: {

            $in:
                moduleAliases

        },

        category:
            category,

        code: {

            $regex:
                `^${escapeRegex(code)}$`,

            $options:
                "i"

        }

    };

    if (excludeId) {

        filter._id = {

            $ne:
                excludeId

        };

    }

    return Lookup.findOne(
        filter
    )
        .lean();

};


// =====================================================
// CREATE SINGLE LOOKUP
// =====================================================

const createLookup = async (
    data,
    organizationId,
    userId
) => {

    const payload =
        data || {};

    const organization =
        normalizeOrganizationId(
            organizationId
        );

    const module =
        normalizeModule(
            payload.module
        );

    const category =
        normalizeCategory(
            payload.category
        );

    const value =
        normalizeValue(
            payload.value
        );

    const code =
        normalizeCode(
            payload.code
        );

    const parentLookup =
        payload.parentLookup
            ? payload.parentLookup
            : null;


    if (!module) {

        throw new Error(
            "Module is required"
        );

    }


    if (!category) {

        throw new Error(
            "Lookup category is required"
        );

    }


    if (!value) {

        throw new Error(
            "Lookup value is required"
        );

    }


    // -------------------------------------------------
    // SYSTEM VALIDATION
    // -------------------------------------------------

    const {
        module:
            validatedModule,

        field

    } =
        validateSystemLookupCategory(
            module,
            category
        );


    // -------------------------------------------------
    // ALLOCATION BEHAVIOR
    // -------------------------------------------------

    let allocationBehavior =
        null;


    if (
        field.category ===
        "ServiceType"
    ) {

        allocationBehavior =
            normalizeAllocationBehavior(
                payload.allocationBehavior
            );

    }


    // -------------------------------------------------
    // PARENT VALIDATION
    // -------------------------------------------------

    const validatedParentLookup =
        await validateParentLookup({

            parentLookup,

            organization,

            module:
                validatedModule,

            category:
                field.category

        });


    // -------------------------------------------------
    // ALLOWED UNITS
    // -------------------------------------------------

    const validatedAllowedUnits =
        await validateAllowedUnits({

            allowedUnits:
                payload.allowedUnits,

            organization,

            module:
                validatedModule,

            category:
                field.category

        });


    // -------------------------------------------------
    // DUPLICATE VALUE
    // -------------------------------------------------

    const existingValue =
        await findExistingLookup(

            organization,

            validatedModule,

            field.category,

            value

        );


    if (existingValue) {

        throw new Error(
            `Lookup value "${value}" already exists in the "${field.category}" category.`
        );

    }


    // -------------------------------------------------
    // DUPLICATE CODE
    // -------------------------------------------------

    if (code) {

        const existingCode =
            await findExistingLookupByCode(

                organization,

                validatedModule,

                field.category,

                code

            );


        if (existingCode) {

            throw new Error(
                `Lookup code "${code}" already exists in the "${field.category}" category.`
            );

        }

    }


    // -------------------------------------------------
    // CREATE
    // -------------------------------------------------

    try {

        const lookup =
            await Lookup.create({

                organization:
                    organization,

                module:
                    validatedModule,

                category:
                    field.category,

                value:
                    value,

                code:
                    code,

                allocationBehavior:
                    allocationBehavior,

                parentLookup:
                    validatedParentLookup,

                allowedUnits:
                    validatedAllowedUnits,

                active:
                    payload.active !== undefined
                        ? normalizeBoolean(
                            payload.active
                        )
                        : true,

                createdBy:
                    userId || null

            });


        return lookup;

    }

    catch (error) {

        if (
            error?.code === 11000
        ) {

            throw new Error(
                "A lookup with the same value or code already exists in this category."
            );

        }

        throw error;

    }

};


// =====================================================
// CREATE MULTIPLE LOOKUPS
// =====================================================

const createLookupsBulk = async (
    module,
    category,
    values,
    organizationId,
    userId,
    active = true
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );

    const normalizedModule =
        normalizeModule(
            module
        );

    const normalizedCategory =
        normalizeCategory(
            category
        );


    if (!normalizedModule) {

        throw new Error(
            "Module is required"
        );

    }


    if (!normalizedCategory) {

        throw new Error(
            "Lookup category is required"
        );

    }


    // -------------------------------------------------
    // SYSTEM VALIDATION
    // -------------------------------------------------

    const {
        module:
            validatedModule,

        field

    } =
        validateSystemLookupCategory(

            normalizedModule,

            normalizedCategory

        );


    // -------------------------------------------------
    // VALUES VALIDATION
    // -------------------------------------------------

    if (
        !Array.isArray(values) ||
        values.length === 0
    ) {

        throw new Error(
            "At least one lookup value is required"
        );

    }


    // -------------------------------------------------
    // CLEAN VALUES
    // -------------------------------------------------

    const cleanedValues =
        values
            .map(
                item => {

                    if (
                        typeof item === "string"
                    ) {

                        return {

                            value:
                                normalizeValue(
                                    item
                                ),

                            code:
                                "",

                            parentLookup:
                                null,

                            allowedUnits:
                                [],

                            allocationBehavior:
                                null

                        };

                    }


                    if (
                        item &&
                        typeof item === "object"
                    ) {

                        return {

                            value:
                                normalizeValue(
                                    item.value
                                ),

                            code:
                                normalizeCode(
                                    item.code
                                ),

                            parentLookup:
                                item.parentLookup
                                    ? item.parentLookup
                                    : null,

                            allowedUnits:
                                item.allowedUnits || [],

                            allocationBehavior:
                                item.allocationBehavior

                        };

                    }


                    return {

                        value:
                            "",

                        code:
                            "",

                        parentLookup:
                            null,

                        allowedUnits:
                            [],

                        allocationBehavior:
                            null

                    };

                }
            )
            .filter(
                item =>
                    Boolean(
                        item.value
                    )
            );


    if (
        cleanedValues.length === 0
    ) {

        throw new Error(
            "Every lookup must have a value"
        );

    }


    // -------------------------------------------------
    // VALIDATE ALLOCATION BEHAVIOR
    // -------------------------------------------------

    for (
        const item
        of cleanedValues
    ) {

        if (
            field.category ===
            "ServiceType"
        ) {

            item.allocationBehavior =
                normalizeAllocationBehavior(
                    item.allocationBehavior
                );

        }

        else {

            item.allocationBehavior =
                null;

        }

    }


    // -------------------------------------------------
    // VALIDATE PARENTS AND ALLOWED UNITS
    // -------------------------------------------------

    for (
        const item
        of cleanedValues
    ) {

        item.parentLookup =
            await validateParentLookup({

                parentLookup:
                    item.parentLookup,

                organization,

                module:
                    validatedModule,

                category:
                    field.category

            });


        item.allowedUnits =
            await validateAllowedUnits({

                allowedUnits:
                    item.allowedUnits,

                organization,

                module:
                    validatedModule,

                category:
                    field.category

            });

    }


    // -------------------------------------------------
    // DUPLICATES INSIDE REQUEST
    // -------------------------------------------------

    const uniqueValues = [];

    const seenValues =
        new Set();

    const seenCodes =
        new Set();


    for (
        const item
        of cleanedValues
    ) {

        const valueKey =
            normalizeValueKey(
                item.value
            );


        if (
            seenValues.has(
                valueKey
            )
        ) {

            throw new Error(
                `Duplicate lookup value "${item.value}" in request.`
            );

        }


        seenValues.add(
            valueKey
        );


        if (item.code) {

            const codeKey =
                normalizeCodeKey(
                    item.code
                );


            if (
                seenCodes.has(
                    codeKey
                )
            ) {

                throw new Error(
                    `Duplicate lookup code "${item.code}" in request.`
                );

            }


            seenCodes.add(
                codeKey
            );

        }


        uniqueValues.push(
            item
        );

    }


    // -------------------------------------------------
    // EXISTING DATABASE VALUES
    // -------------------------------------------------

    const moduleAliases =
        getModuleAliases(
            validatedModule
        );


    const existing =
        await Lookup.find({

            organization:
                organization,

            module: {

                $in:
                    moduleAliases

            },

            category:
                field.category

        })
        .select(
            "module category value code parentLookup allowedUnits allocationBehavior"
        )
        .lean();


    // -------------------------------------------------
    // EXISTING VALUE/CODE MAPS
    // -------------------------------------------------

    const existingValues =
        new Set(

            existing.map(

                item =>
                    normalizeValueKey(
                        item.value
                    )

            )

        );


    const existingCodes =
        new Set(

            existing
                .map(
                    item =>
                        normalizeCodeKey(
                            item.code
                        )
                )
                .filter(
                    Boolean
                )

        );


    // -------------------------------------------------
    // VALIDATE AGAINST DATABASE
    // -------------------------------------------------

    for (
        const item
        of uniqueValues
    ) {

        const valueKey =
            normalizeValueKey(
                item.value
            );


        if (
            existingValues.has(
                valueKey
            )
        ) {

            throw new Error(
                `Lookup value "${item.value}" already exists in the "${field.category}" category.`
            );

        }


        if (item.code) {

            const codeKey =
                normalizeCodeKey(
                    item.code
                );


            if (
                existingCodes.has(
                    codeKey
                )
            ) {

                throw new Error(
                    `Lookup code "${item.code}" already exists in the "${field.category}" category.`
                );

            }

        }

    }


    // -------------------------------------------------
    // BUILD DOCUMENTS
    // -------------------------------------------------

    const documents =
        uniqueValues.map(

            item => ({

                organization:
                    organization,

                module:
                    validatedModule,

                category:
                    field.category,

                value:
                    item.value,

                code:
                    item.code,

                allocationBehavior:
                    item.allocationBehavior,

                parentLookup:
                    item.parentLookup,

                allowedUnits:
                    item.allowedUnits,

                active:
                    normalizeBoolean(
                        active
                    ),

                createdBy:
                    userId || null

            })

        );


    // -------------------------------------------------
    // INSERT
    // -------------------------------------------------

    try {

        return await Lookup.insertMany(
            documents
        );

    }

    catch (error) {

        if (
            error?.code === 11000
        ) {

            throw new Error(
                `One or more lookup values or codes already exist in the "${field.category}" category.`
            );

        }

        throw error;

    }

};


// =====================================================
// GET ALL LOOKUPS
// =====================================================

const getLookups = async (
    organizationId,
    query = {}
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    const filter = {

        organization:
            organization

    };


    // -------------------------------------------------
    // MODULE
    // -------------------------------------------------

    if (
        query.module !== undefined
    ) {

        const module =
            normalizeModule(
                query.module
            );


        if (module) {

            filter.module = {

                $in:
                    getModuleAliases(
                        module
                    )

            };

        }

    }


    // -------------------------------------------------
    // CATEGORY
    // -------------------------------------------------

    if (
        query.category !== undefined
    ) {

        const category =
            normalizeCategory(
                query.category
            );


        if (category) {

            filter.category =
                category;

        }

    }


    // -------------------------------------------------
    // PARENT LOOKUP
    // -------------------------------------------------

    if (
        query.parentLookup !== undefined
    ) {

        if (
            query.parentLookup === null ||
            query.parentLookup === ""
        ) {

            filter.parentLookup =
                null;

        }

        else if (
            mongoose.Types.ObjectId.isValid(
                query.parentLookup
            )
        ) {

            filter.parentLookup =
                query.parentLookup;

        }

    }


    // -------------------------------------------------
    // ACTIVE
    // -------------------------------------------------

    if (
        query.active !== undefined
    ) {

        if (
            query.active === true ||
            query.active === "true"
        ) {

            filter.active =
                true;

        }

        else if (
            query.active === false ||
            query.active === "false"
        ) {

            filter.active =
                false;

        }

    }


    // -------------------------------------------------
    // SEARCH
    // -------------------------------------------------

    if (
        query.search !== undefined
    ) {

        const search =
            normalizeString(
                query.search
            );


        if (search) {

            filter.value = {

                $regex:
                    escapeRegex(
                        search
                    ),

                $options:
                    "i"

            };

        }

    }


    // -------------------------------------------------
    // RESULT
    // -------------------------------------------------

    const rows =
        await Lookup.find(
            filter
        )
        .sort({

            module:
                1,

            category:
                1,

            value:
                1

        });


    // -------------------------------------------------
    // NORMALIZE RESPONSE
    // -------------------------------------------------

    return rows.map(

        lookup => {

            const object =
                lookup.toObject
                    ? lookup.toObject()
                    : Object.assign(
                        {},
                        lookup
                    );


            object.module =
                normalizeModule(
                    object.module
                );


            // -------------------------------------------------
            // BACKWARD COMPATIBILITY
            // -------------------------------------------------

            if (
                object.module ===
                    "ServiceDelivery" &&
                object.category ===
                    "ServiceType" &&
                !object.allocationBehavior
            ) {

                object.allocationBehavior =
                    "CONSUMPTION";

            }


            return object;

        }

    );

};


// =====================================================
// GET LOOKUP CATEGORIES BY MODULE
// =====================================================

const getLookupCategoriesByModule = async (
    module,
    organizationId
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    const normalizedModule =
        normalizeModule(
            module
        );


    if (!normalizedModule) {

        throw new Error(
            "Module is required"
        );

    }


    const categories =
        getSystemLookupCategories(
            normalizedModule
        );


    if (
        !Array.isArray(categories) ||
        categories.length === 0
    ) {

        throw new Error(
            `No system lookup categories are defined for module "${normalizedModule}"`
        );

    }


    const moduleAliases =
        getModuleAliases(
            normalizedModule
        );


    // -------------------------------------------------
    // COUNT ORGANIZATION VALUES
    // -------------------------------------------------

    const counts =
        await Lookup.aggregate([

            {

                $match: {

                    organization:
                        organization,

                    module: {

                        $in:
                            moduleAliases

                    }

                }

            },

            {

                $group: {

                    _id:
                        "$category",

                    count: {

                        $sum:
                            1

                    },

                    activeCount: {

                        $sum: {

                            $cond: [

                                "$active",

                                1,

                                0

                            ]

                        }

                    }

                }

            }

        ]);


    const countMap =
        new Map(

            counts.map(

                item => [

                    item._id,

                    {

                        count:
                            item.count,

                        activeCount:
                            item.activeCount

                    }

                ]

            )

        );


    // -------------------------------------------------
    // RETURN SYSTEM DEFINITIONS
    // -------------------------------------------------

    return categories.map(

        field => {

            const stats =
                countMap.get(
                    field.category
                ) || {

                    count:
                        0,

                    activeCount:
                        0

                };


            return {

                field:
                    field.field,

                category:
                    field.category,

                label:
                    field.label,

                multiple:
                    field.multiple,

                dependsOn:
                    field.dependsOn || null,

                lookupCount:
                    stats.count,

                activeLookupCount:
                    stats.activeCount

            };

        }

    );

};


// =====================================================
// GET LOOKUPS BY CATEGORY
// =====================================================

const getLookupByCategory = async (
    category,
    organizationId,
    parentLookup = null
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    const normalizedCategory =
        normalizeCategory(
            category
        );


    if (!normalizedCategory) {

        throw new Error(
            "Lookup category is required"
        );

    }


    const filter = {

        organization:
            organization,

        category:
            normalizedCategory,

        active:
            true

    };


    // -------------------------------------------------
    // ServiceType filtering
    // -------------------------------------------------

    if (
        normalizedCategory === "ServiceType"
    ) {

        if (
            !parentLookup ||
            !mongoose.Types.ObjectId.isValid(
                parentLookup
            )
        ) {

            return [];

        }


        filter.parentLookup =
            parentLookup;

    }


    const rows =
        await Lookup.find(
            filter
        )
        .sort({

            value:
                1

        });


    return rows.map(

        lookup => {

            const object =
                lookup.toObject
                    ? lookup.toObject()
                    : Object.assign(
                        {},
                        lookup
                    );


            if (
                object.category ===
                "ServiceType" &&
                !object.allocationBehavior
            ) {

                object.allocationBehavior =
                    "CONSUMPTION";

            }


            return object;

        }

    );

};


// =====================================================
// GET LOOKUPS BY MODULE + CATEGORY
// =====================================================

const getLookupByModuleAndCategory = async (
    module,
    category,
    organizationId,
    parentLookup = null
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    const {
        module:
            validatedModule,

        field

    } =
        validateSystemLookupCategory(

            module,

            category

        );


    const moduleAliases =
        getModuleAliases(
            validatedModule
        );


    const filter = {

        organization:
            organization,

        module: {

            $in:
                moduleAliases

        },

        category:
            field.category,

        active:
            true

    };


    // -------------------------------------------------
    // ServiceType parent filtering
    // -------------------------------------------------
    //
    // ServiceCategory is the parent of ServiceType.
    //
    // If parentLookup is supplied:
    //
    // ServiceCategory
    //       ↓
    // ServiceType
    //
    // only children of that category are returned.
    //
    // If parentLookup is omitted:
    // all ServiceTypes are returned.
    //
    // -------------------------------------------------

    if (
        field.category === "ServiceType" &&
        parentLookup
    ) {

        if (
            !mongoose.Types.ObjectId.isValid(
                parentLookup
            )
        ) {

            return [];

        }


        const parent =
            await Lookup.findOne({

                _id:
                    parentLookup,

                organization:
                    organization,

                module:
                    validatedModule,

                category:
                    "ServiceCategory",

                active:
                    true

            })
            .select(
                "_id"
            )
            .lean();


        if (!parent) {

            return [];

        }


        filter.parentLookup =
            parent._id;

    }


    const rows =
        await Lookup.find(
            filter
        )
        .sort({

            value:
                1

        });


    // -------------------------------------------------
    // NORMALIZE RESPONSE
    // -------------------------------------------------

    return rows.map(

        lookup => {

            const object =
                lookup.toObject
                    ? lookup.toObject()
                    : Object.assign(
                        {},
                        lookup
                    );


            object.module =
                validatedModule;


            object.category =
                field.category;


            // -------------------------------------------------
            // BACKWARD COMPATIBILITY
            // -------------------------------------------------

            if (
                field.category ===
                    "ServiceType" &&
                !object.allocationBehavior
            ) {

                object.allocationBehavior =
                    "CONSUMPTION";

            }


            return object;

        }

    );

};


// =====================================================
// GET SINGLE LOOKUP
// =====================================================

const getLookupById = async (
    id,
    organizationId
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    if (
        !mongoose.Types.ObjectId.isValid(
            id
        )
    ) {

        throw new Error(
            "Invalid lookup ID"
        );

    }


    const lookup =
        await Lookup.findOne({

            _id:
                id,

            organization:
                organization

        });


    if (!lookup) {

        throw new Error(
            "Lookup not found"
        );

    }


    lookup.module =
        normalizeModule(
            lookup.module
        );


    if (
        lookup.module ===
            "ServiceDelivery" &&
        lookup.category ===
            "ServiceType" &&
        !lookup.allocationBehavior
    ) {

        lookup.allocationBehavior =
            "CONSUMPTION";

    }


    return lookup;

};


// =====================================================
// UPDATE LOOKUP
// =====================================================

const updateLookup = async (
    id,
    data,
    organizationId,
    userId
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    if (
        !mongoose.Types.ObjectId.isValid(
            id
        )
    ) {

        throw new Error(
            "Invalid lookup ID"
        );

    }


    const lookup =
        await Lookup.findOne({

            _id:
                id,

            organization:
                organization

        });


    if (!lookup) {

        throw new Error(
            "Lookup not found"
        );

    }


    const payload =
        data || {};


    const currentModule =
        normalizeModule(
            lookup.module
        );


    const currentCategory =
        normalizeCategory(
            lookup.category
        );


    // -------------------------------------------------
    // RESOLVE CURRENT SYSTEM DEFINITION
    // -------------------------------------------------

    const {
        module:
            validatedCurrentModule,

        field:
            currentField

    } =
        validateSystemLookupCategory(

            currentModule,

            currentCategory

        );


    // -------------------------------------------------
    // MODULE CANNOT CHANGE
    // -------------------------------------------------

    if (
        payload.module !== undefined
    ) {

        const requestedModule =
            normalizeModule(
                payload.module
            );


        if (
            requestedModule !==
            validatedCurrentModule
        ) {

            throw new Error(
                "Lookup module cannot be changed after creation."
            );

        }

    }


    // -------------------------------------------------
    // CATEGORY CANNOT CHANGE
    // -------------------------------------------------

    if (
        payload.category !== undefined
    ) {

        const requestedCategory =
            normalizeCategory(
                payload.category
            );


        const requestedField =
            getSystemLookupFieldByCategory(

                validatedCurrentModule,

                requestedCategory

            );


        if (!requestedField) {

            throw new Error(
                `Lookup category "${requestedCategory}" is not allowed for module "${validatedCurrentModule}"`
            );

        }


        if (
            requestedField.category !==
            currentField.category
        ) {

            throw new Error(
                "Lookup category cannot be changed after creation."
            );

        }

    }


    // -------------------------------------------------
    // UPDATE DATA
    // -------------------------------------------------

    const updateData = {

        updatedBy:
            userId || null

    };


    // -------------------------------------------------
    // VALUE
    // -------------------------------------------------

    let finalValue =
        normalizeValue(
            lookup.value
        );


    if (
        payload.value !== undefined
    ) {

        finalValue =
            normalizeValue(
                payload.value
            );


        if (!finalValue) {

            throw new Error(
                "Lookup value is required"
            );

        }


        updateData.value =
            finalValue;

    }


    // -------------------------------------------------
    // CODE
    // -------------------------------------------------

    let finalCode =
        normalizeCode(
            lookup.code
        );


    if (
        payload.code !== undefined
    ) {

        finalCode =
            normalizeCode(
                payload.code
            );


        updateData.code =
            finalCode;

    }


    // -------------------------------------------------
    // ALLOCATION BEHAVIOR
    // -------------------------------------------------
    //
    // Only ServiceType can have allocation behavior.
    //
    // Existing ServiceTypes without a value are treated
    // as CONSUMPTION.
    //
    // -------------------------------------------------

    if (
        currentField.category ===
        "ServiceType"
    ) {

        const currentAllocationBehavior =
            lookup.allocationBehavior ||
            "CONSUMPTION";


        const finalAllocationBehavior =
            payload.allocationBehavior !== undefined
                ? normalizeAllocationBehavior(
                    payload.allocationBehavior
                )
                : normalizeAllocationBehavior(
                    currentAllocationBehavior
                );


        updateData.allocationBehavior =
            finalAllocationBehavior;

    }

    else {

        updateData.allocationBehavior =
            null;

    }


    // -------------------------------------------------
    // PARENT LOOKUP
    // -------------------------------------------------
    //
    // IMPORTANT:
    //
    // ServiceType.parentLookup remains the
    // ServiceCategory.
    //
    // -------------------------------------------------

    let finalParentLookup =
        lookup.parentLookup
            ? String(
                lookup.parentLookup
            )
            : null;


    if (
        payload.parentLookup !== undefined
    ) {

        finalParentLookup =
            payload.parentLookup
                ? String(
                    payload.parentLookup
                )
                : null;

    }


    finalParentLookup =
        await validateParentLookup({

            parentLookup:
                finalParentLookup,

            organization,

            module:
                validatedCurrentModule,

            category:
                currentField.category

        });


    updateData.parentLookup =
        finalParentLookup;


    // -------------------------------------------------
    // ALLOWED UNITS
    // -------------------------------------------------
    //
    // Only ServiceType can have Allowed Units.
    //
    // -------------------------------------------------

    let finalAllowedUnits = [];


    if (
        currentField.category ===
        "ServiceType"
    ) {

        if (
            payload.allowedUnits !== undefined
        ) {

            finalAllowedUnits =
                await validateAllowedUnits({

                    allowedUnits:
                        payload.allowedUnits,

                    organization,

                    module:
                        validatedCurrentModule,

                    category:
                        currentField.category

                });

        }

        else {

            finalAllowedUnits =
                await validateAllowedUnits({

                    allowedUnits:
                        lookup.allowedUnits,

                    organization,

                    module:
                        validatedCurrentModule,

                    category:
                        currentField.category

                });

        }


        updateData.allowedUnits =
            finalAllowedUnits;

    }

    else {

        updateData.allowedUnits =
            [];

    }


    // -------------------------------------------------
    // ACTIVE
    // -------------------------------------------------

    if (
        payload.active !== undefined
    ) {

        updateData.active =
            normalizeBoolean(
                payload.active
            );

    }


    // -------------------------------------------------
    // DUPLICATE VALUE
    // -------------------------------------------------

    const duplicateValue =
        await findExistingLookup(

            organization,

            validatedCurrentModule,

            currentField.category,

            finalValue,

            id

        );


    if (
        duplicateValue
    ) {

        throw new Error(
            `Lookup value "${finalValue}" already exists in the "${currentField.category}" category.`
        );

    }


    // -------------------------------------------------
    // DUPLICATE CODE
    // -------------------------------------------------

    if (finalCode) {

        const duplicateCode =
            await findExistingLookupByCode(

                organization,

                validatedCurrentModule,

                currentField.category,

                finalCode,

                id

            );


        if (
            duplicateCode
        ) {

            throw new Error(
                `Lookup code "${finalCode}" already exists in the "${currentField.category}" category.`
            );

        }

    }


    // -------------------------------------------------
    // UPDATE
    // -------------------------------------------------

    const updatedLookup =
        await Lookup.findOneAndUpdate(

            {

                _id:
                    id,

                organization:
                    organization

            },

            {

                $set:
                    updateData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        );


    if (!updatedLookup) {

        throw new Error(
            "Lookup not found"
        );

    }


    return updatedLookup;

};


// =====================================================
// DELETE / DEACTIVATE
// =====================================================

const deleteLookup = async (
    id,
    organizationId,
    userId = null
) => {

    const organization =
        normalizeOrganizationId(
            organizationId
        );


    if (
        !mongoose.Types.ObjectId.isValid(
            id
        )
    ) {

        throw new Error(
            "Invalid lookup ID"
        );

    }


    const updateData = {

        active:
            false

    };


    if (userId) {

        updateData.updatedBy =
            userId;

    }


    const lookup =
        await Lookup.findOneAndUpdate(

            {

                _id:
                    id,

                organization:
                    organization

            },

            {

                $set:
                    updateData

            },

            {

                new:
                    true

            }

        );


    if (!lookup) {

        throw new Error(
            "Lookup not found"
        );

    }


    return lookup;

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    createLookup,

    createLookupsBulk,

    getLookups,

    getLookupCategoriesByModule,

    getLookupByCategory,

    getLookupByModuleAndCategory,

    getLookupById,

    updateLookup,

    deleteLookup

};