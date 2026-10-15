import {
    getLookupsApi,
    getLookupsByModuleAndCategoryApi,
    getLookupCategoriesByModuleApi,
    getLookupByIdApi,
    createLookupApi,
    createLookupsBulkApi,
    updateLookupApi,
    deleteLookupApi,
    getBeneficiariesLookupApi
} from "../api/lookupApi";


// =====================================================
// MODULE ALIASES
// =====================================================

const MODULE_ALIASES = {

    beneficiary: "Beneficiary",
    beneficiaries: "Beneficiary",

    enterprise: "Enterprise",
    enterprises: "Enterprise",

    "enterprise-member": "EnterpriseMember",
    "enterprise-members": "EnterpriseMember",
    enterprisemember: "EnterpriseMember",

    program: "Program",
    programs: "Program",

    project: "Project",
    projects: "Project",

    activity: "Activity",
    activities: "Activity",

    "activity-run": "ActivityRun",
    "activity-runs": "ActivityRun",
    activityrun: "ActivityRun",

    attendance: "Attendance",

    enrollment: "Enrollment",
    enrollments: "Enrollment",

    servicedelivery: "ServiceDelivery",
    "service-delivery": "ServiceDelivery",
    "service-deliveries": "ServiceDelivery",

    user: "User",
    users: "User",

    donor: "Donor",
    donors: "Donor",

    donation: "Donation",
    donations: "Donation"

};


// =====================================================
// CANONICAL MODULE LABELS
// =====================================================

const MODULE_LABELS = {

    Beneficiary: "Beneficiaries",

    Enterprise: "Enterprises",

    EnterpriseMember: "Enterprise Members",

    Program: "Programs",

    Project: "Projects",

    Activity: "Activities",

    ActivityRun: "Activity Runs",

    Attendance: "Attendance",

    Enrollment: "Enrollments",

    ServiceDelivery: "Service Delivery",

    User: "Users",

    Donor: "Donors",

    Donation: "Donations"

};


// =====================================================
// NORMALIZE MODULE
// =====================================================

const normalizeModule = (
    module
) => {

    if (
        module === undefined ||
        module === null
    ) {

        return "";

    }


    const value =
        String(module).trim();


    if (!value) {

        return "";

    }


    const lower =
        value.toLowerCase();


    if (
        MODULE_ALIASES[lower]
    ) {

        return MODULE_ALIASES[lower];

    }


    const canonicalModule =
        Object.keys(
            MODULE_LABELS
        ).find(
            moduleName =>
                moduleName.toLowerCase() ===
                lower
        );


    if (canonicalModule) {

        return canonicalModule;

    }


    return value;

};


// =====================================================
// GET MODULE LABEL
// =====================================================

const getLookupModuleLabel = (
    module
) => {

    const normalized =
        normalizeModule(module);


    return (
        MODULE_LABELS[normalized] ||
        normalized ||
        "Unknown"
    );

};


// =====================================================
// NORMALIZE CATEGORY
// =====================================================

const normalizeCategory = (
    category
) => {

    if (
        category === undefined ||
        category === null
    ) {

        return "";

    }


    return String(
        category
    ).trim();

};


// =====================================================
// NORMALIZE OBJECT ID
// =====================================================

const normalizeObjectId = (
    value
) => {

    if (
        value === undefined ||
        value === null
    ) {

        return "";

    }


    if (
        typeof value === "object" &&
        value !== null
    ) {

        return String(
            value?._id ||
            value?.id ||
            ""
        ).trim();

    }


    return String(
        value
    ).trim();

};


// =====================================================
// NORMALIZE OBJECT ID ARRAY
// =====================================================

const normalizeObjectIdArray = (
    values
) => {

    if (!Array.isArray(values)) {

        return [];

    }


    const result = [];
    const seen = new Set();


    values.forEach(
        value => {

            const normalizedId =
                normalizeObjectId(
                    value
                );


            if (
                !normalizedId ||
                seen.has(normalizedId)
            ) {

                return;

            }


            seen.add(
                normalizedId
            );


            result.push(
                normalizedId
            );

        }
    );


    return result;

};


// =====================================================
// GET ALL LOOKUPS
// =====================================================

export const getLookupsService = async (
    params = {}
) => {

    const normalizedParams =
        Object.assign(
            {},
            params
        );


    if (
        normalizedParams.module !== undefined
    ) {

        normalizedParams.module =
            normalizeModule(
                normalizedParams.module
            );

    }


    if (
        normalizedParams.category !== undefined
    ) {

        normalizedParams.category =
            normalizeCategory(
                normalizedParams.category
            );

    }


    if (
        normalizedParams.parentLookup !== undefined &&
        normalizedParams.parentLookup !== null &&
        String(
            normalizedParams.parentLookup
        ).trim() !== ""
    ) {

        normalizedParams.parentLookup =
            normalizeObjectId(
                normalizedParams.parentLookup
            );

    }


    if (
        normalizedParams.allowedUnits !== undefined
    ) {

        normalizedParams.allowedUnits =
            normalizeObjectIdArray(
                normalizedParams.allowedUnits
            );

    }


    return getLookupsApi(
        normalizedParams
    );

};


// =====================================================
// GET LOOKUP CATEGORIES BY MODULE
// =====================================================

export const getLookupCategoriesByModuleService =
    async (
        module
    ) => {

        const normalizedModule =
            normalizeModule(module);


        if (!normalizedModule) {

            throw new Error(
                "Lookup module is required"
            );

        }


        return getLookupCategoriesByModuleApi(
            normalizedModule
        );

    };


// =====================================================
// GET LOOKUPS BY MODULE + CATEGORY
// =====================================================
//
// Supports dependent lookups.
//
// Example:
//
// ServiceCategory:
// getLookupsByModuleAndCategoryService(
//     "ServiceDelivery",
//     "ServiceCategory"
// );
//
// ServiceType:
// getLookupsByModuleAndCategoryService(
//     "ServiceDelivery",
//     "ServiceType",
//     categoryId
// );
//
// Unit:
// getLookupsByModuleAndCategoryService(
//     "ServiceDelivery",
//     "Unit"
// );
//
// =====================================================

export const getLookupsByModuleAndCategoryService =
    async (
        module,
        category,
        parentLookup = null
    ) => {

        const normalizedModule =
            normalizeModule(module);


        const normalizedCategory =
            normalizeCategory(category);


        if (!normalizedModule) {

            throw new Error(
                "Lookup module is required"
            );

        }


        if (!normalizedCategory) {

            throw new Error(
                "Lookup category is required"
            );

        }


        let normalizedParentLookup =
            null;


        if (
            parentLookup !== undefined &&
            parentLookup !== null &&
            String(parentLookup).trim() !== ""
        ) {

            normalizedParentLookup =
                normalizeObjectId(
                    parentLookup
                );

        }


        return getLookupsByModuleAndCategoryApi(

            normalizedModule,

            normalizedCategory,

            normalizedParentLookup

        );

    };


// =====================================================
// GET LOOKUPS BY CATEGORY
// =====================================================
//
// Compatibility helper.
//
// Also supports parentLookup.
//
// =====================================================

export const getLookupsByCategoryService =
    async (
        module,
        category,
        parentLookup = null
    ) => {

        return getLookupsByModuleAndCategoryService(

            module,

            category,

            parentLookup

        );

    };


// =====================================================
// GET SINGLE LOOKUP
// =====================================================

export const getLookupByIdService = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    return getLookupByIdApi(
        id
    );

};


// =====================================================
// CREATE SINGLE LOOKUP
// =====================================================

export const createLookupService = async (
    data = {}
) => {

    const payload =
        Object.assign(
            {},
            data
        );


    if (
        payload.module !== undefined
    ) {

        payload.module =
            normalizeModule(
                payload.module
            );

    }


    if (
        payload.category !== undefined
    ) {

        payload.category =
            normalizeCategory(
                payload.category
            );

    }


    if (!payload.module) {

        throw new Error(
            "Lookup module is required"
        );

    }


    if (!payload.category) {

        throw new Error(
            "Lookup category is required"
        );

    }


    if (
        !String(
            payload.value || ""
        ).trim()
    ) {

        throw new Error(
            "Lookup value is required"
        );

    }


    payload.value =
        String(
            payload.value
        ).trim();


    if (
        payload.code !== undefined &&
        payload.code !== null
    ) {

        payload.code =
            String(
                payload.code
            ).trim();

    }


    // -------------------------------------------------
    // PARENT LOOKUP
    // -------------------------------------------------

    if (
        payload.parentLookup !== undefined &&
        payload.parentLookup !== null &&
        String(payload.parentLookup).trim() !== ""
    ) {

        payload.parentLookup =
            normalizeObjectId(
                payload.parentLookup
            );

    }

    else {

        delete payload.parentLookup;

    }


    // -------------------------------------------------
    // ALLOWED UNITS
    // -------------------------------------------------
    //
    // Used by ServiceType.
    //
    // ServiceCategory does not use allowedUnits.
    //
    // There is no default unit.
    //
    // -------------------------------------------------

    if (
        payload.allowedUnits !== undefined
    ) {

        payload.allowedUnits =
            normalizeObjectIdArray(
                payload.allowedUnits
            );

    }


    return createLookupApi(
        payload
    );

};


// =====================================================
// CREATE BULK LOOKUPS
// =====================================================
//
// Supports:
//
// values: [
//     {
//         value: "Medical Consultation",
//         code: "MEDICAL_CONSULTATION",
//         parentLookup: "<HealthCategoryId>",
//         allowedUnits: [
//             "<SessionUnitId>"
//         ]
//     }
// ]
//
// =====================================================

export const createLookupsBulkService =
    async (
        data = {}
    ) => {

        const payload =
            Object.assign(
                {},
                data
            );


        if (
            payload.module !== undefined
        ) {

            payload.module =
                normalizeModule(
                    payload.module
                );

        }


        if (
            payload.category !== undefined
        ) {

            payload.category =
                normalizeCategory(
                    payload.category
                );

        }


        if (!payload.module) {

            throw new Error(
                "Lookup module is required"
            );

        }


        if (!payload.category) {

            throw new Error(
                "Lookup category is required"
            );

        }


        if (
            !Array.isArray(
                payload.values
            ) ||
            payload.values.length === 0
        ) {

            throw new Error(
                "At least one lookup value is required"
            );

        }


        payload.values =
            payload.values.map(
                item => {

                    const normalizedItem = {

                        value:
                            String(
                                item?.value || ""
                            ).trim(),

                        code:
                            item?.code !== undefined &&
                            item?.code !== null

                                ? String(
                                    item.code
                                ).trim()

                                : ""

                    };


                    // -----------------------------------------
                    // PARENT LOOKUP
                    // -----------------------------------------

                    if (
                        item?.parentLookup !== undefined &&
                        item?.parentLookup !== null &&
                        String(
                            item.parentLookup
                        ).trim() !== ""
                    ) {

                        normalizedItem.parentLookup =
                            normalizeObjectId(
                                item.parentLookup
                            );

                    }


                    // -----------------------------------------
                    // ALLOWED UNITS
                    // -----------------------------------------

                    if (
                        item?.allowedUnits !== undefined
                    ) {

                        normalizedItem.allowedUnits =
                            normalizeObjectIdArray(
                                item.allowedUnits
                            );

                    }


                    return normalizedItem;

                }
            );


        if (
            payload.values.some(
                item => !item.value
            )
        ) {

            throw new Error(
                "Every lookup must have a value"
            );

        }


        return createLookupsBulkApi(
            payload
        );

    };


// =====================================================
// UPDATE LOOKUP
// =====================================================
//
// ServiceType can update:
//
// 1. parentLookup
// 2. allowedUnits
//
// parentLookup remains the ServiceCategory relationship.
//
// allowedUnits is the ServiceType -> Unit relationship.
//
// There is no default unit.
//
// =====================================================

export const updateLookupService = async (
    id,
    data = {}
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    const payload =
        Object.assign(
            {},
            data
        );


    if (
        payload.module !== undefined
    ) {

        payload.module =
            normalizeModule(
                payload.module
            );

    }


    if (
        payload.category !== undefined
    ) {

        payload.category =
            normalizeCategory(
                payload.category
            );

    }


    if (
        payload.value !== undefined &&
        payload.value !== null
    ) {

        payload.value =
            String(
                payload.value
            ).trim();

    }


    if (
        payload.code !== undefined &&
        payload.code !== null
    ) {

        payload.code =
            String(
                payload.code
            ).trim();

    }


    // -------------------------------------------------
    // PARENT LOOKUP
    // -------------------------------------------------

    if (
        payload.parentLookup !== undefined &&
        payload.parentLookup !== null &&
        String(payload.parentLookup).trim() !== ""
    ) {

        payload.parentLookup =
            normalizeObjectId(
                payload.parentLookup
            );

    }

    else if (
        payload.parentLookup === null ||
        payload.parentLookup === ""
    ) {

        payload.parentLookup = null;

    }


    // -------------------------------------------------
    // ALLOWED UNITS
    // -------------------------------------------------

    if (
        payload.allowedUnits !== undefined
    ) {

        payload.allowedUnits =
            normalizeObjectIdArray(
                payload.allowedUnits
            );

    }


    return updateLookupApi(
        id,
        payload
    );

};


// =====================================================
// DELETE / DEACTIVATE LOOKUP
// =====================================================

export const deleteLookupService = async (
    id
) => {

    if (!id) {

        throw new Error(
            "Lookup ID is required"
        );

    }


    return deleteLookupApi(
        id
    );

};


// =====================================================
// LOOKUP OPTIONS
// =====================================================
//
// Preferred:
//
// getLookupOptionsService(
//     "Beneficiary",
//     "Gender"
// )
//
// Dependent:
//
// getLookupOptionsService(
//     "ServiceDelivery",
//     "ServiceType",
//     categoryId
// )
//
// Service Delivery Units:
//
// getLookupOptionsService(
//     "ServiceDelivery",
//     "Unit"
// )
//
// Backward compatibility:
//
// getLookupOptionsService(
//     "Gender"
// )
//
// =====================================================

export const getLookupOptionsService =
    async (
        moduleOrCategory,
        maybeCategory,
        parentLookup = null
    ) => {

        let module;
        let category;


        // ---------------------------------------------
        // NEW FORMAT
        // ---------------------------------------------

        if (
            maybeCategory !== undefined
        ) {

            module =
                normalizeModule(
                    moduleOrCategory
                );


            category =
                normalizeCategory(
                    maybeCategory
                );

        }


        // ---------------------------------------------
        // BACKWARD COMPATIBILITY
        // ---------------------------------------------

        else {

            module =
                "Beneficiary";


            category =
                normalizeCategory(
                    moduleOrCategory
                );

        }


        if (
            !module ||
            !category
        ) {

            return [];

        }


        const response =
            await getLookupsByModuleAndCategoryService(

                module,

                category,

                parentLookup

            );


        if (
            Array.isArray(response)
        ) {

            return response;

        }


        if (
            Array.isArray(
                response?.data
            )
        ) {

            return response.data;

        }


        if (
            Array.isArray(
                response?.data?.data
            )
        ) {

            return response.data.data;

        }


        return [];

    };


// =====================================================
// BENEFICIARY ENTITY LOOKUP
// =====================================================
//
// Different from system lookup values.
//
// =====================================================

export const getBeneficiariesLookupService =
    async (
        params = {}
    ) => {

        return getBeneficiariesLookupApi(
            params
        );

    };


// =====================================================
// EXPORT HELPERS
// =====================================================

export {
    normalizeModule,
    normalizeCategory,
    getLookupModuleLabel,
    normalizeObjectId,
    normalizeObjectIdArray
};