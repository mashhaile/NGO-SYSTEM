// =====================================================
// SYSTEM LOOKUP FIELD DEFINITIONS
// =====================================================
//
// These are ONLY BUILT-IN SYSTEM FIELDS that use Lookup.
//
// NOT CustomFields.
//
// CustomFields that use:
//
//     optionSource: "lookup"
//
// are managed separately.
//
// Architecture:
//
//     Module
//        ↓
//     System Lookup Category
//        ↓
//     Organization Lookup Values
//
// Organizations manage the VALUES.
// The system controls the available CATEGORIES.
//
// =====================================================


const SYSTEM_LOOKUP_FIELDS = {

    // =================================================
    // BENEFICIARY
    // =================================================

    Beneficiary: [

        {
            field: "gender",
            category: "Gender",
            label: "Gender",
            multiple: false
        },

        {
            field: "educationLevel",
            category: "EducationLevel",
            label: "Education Level",
            multiple: false
        },

        {
            field: "occupation",
            category: "Occupation",
            label: "Occupation",
            multiple: false
        },

        {
            field: "maritalStatus",
            category: "MaritalStatus",
            label: "Marital Status",
            multiple: false
        },

        {
            field: "disabilityType",
            category: "DisabilityType",
            label: "Disability Type",
            multiple: false
        },

        {
            field: "vulnerableGroups",
            category: "VulnerableGroup",
            label: "Vulnerable Groups",
            multiple: true
        }

    ],


    // =================================================
    // ENTERPRISE
    // =================================================

    Enterprise: [

        {
            field: "enterpriseType",
            category: "EnterpriseType",
            label: "Enterprise Type",
            multiple: false
        },

        {
            field: "ownershipType",
            category: "OwnershipType",
            label: "Ownership Type",
            multiple: false
        },

        {
            field: "businessSector",
            category: "BusinessSector",
            label: "Business Sector",
            multiple: false
        }

    ],


    // =================================================
    // SERVICE DELIVERY
    // =================================================

    // =================================================
    // PROJECT
    // =================================================

    Project: [

        {
            field: "projectType",
            category: "ProjectType",
            label: "Project Type",
            multiple: false
        }

    ],


    ServiceDelivery: [

        {
            field: "serviceCategory",
            category: "ServiceCategory",
            label: "Service Category",
            multiple: false
        },

        {
            field: "serviceType",
            category: "ServiceType",
            label: "Service Type",
            multiple: false,

            // Service Type depends on Service Category
            dependsOn: "ServiceCategory"
        },

        {
            field: "unit",
            category: "Unit",
            label: "Unit",
            multiple: false
        }

    ]

};


// =====================================================
// MODULE ALIASES
// =====================================================

const MODULE_ALIASES = {


    // -------------------------------------------------
    // BENEFICIARY
    // -------------------------------------------------

    beneficiary:
        "Beneficiary",

    beneficiaries:
        "Beneficiary",


    // -------------------------------------------------
    // ENTERPRISE
    // -------------------------------------------------

    enterprise:
        "Enterprise",

    enterprises:
        "Enterprise",


    // -------------------------------------------------
    // DONOR
    // -------------------------------------------------

    donor:
        "Donor",

    donors:
        "Donor",


    // -------------------------------------------------
    // PROGRAM
    // -------------------------------------------------

    program:
        "Program",

    programs:
        "Program",


    // -------------------------------------------------
    // PROJECT
    // -------------------------------------------------

    project:
        "Project",

    projects:
        "Project",


    // -------------------------------------------------
    // PROJECT
    // -------------------------------------------------

    project:
        "Project",

    projects:
        "Project",


    // -------------------------------------------------
    // USER
    // -------------------------------------------------

    user:
        "User",

    users:
        "User",


    // -------------------------------------------------
    // ENTERPRISE MEMBER
    // -------------------------------------------------

    "enterprise-member":
        "EnterpriseMember",

    "enterprise-members":
        "EnterpriseMember",


    // -------------------------------------------------
    // SERVICE DELIVERY
    // -------------------------------------------------

    servicedelivery:
        "ServiceDelivery",

    "service-delivery":
        "ServiceDelivery",

    "service-deliveries":
        "ServiceDelivery"

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
        String(module)
            .trim();


    if (!value) {

        return "";

    }


    const lowerValue =
        value.toLowerCase();


    // -------------------------------------------------
    // ALIAS
    // -------------------------------------------------

    if (
        MODULE_ALIASES[
            lowerValue
        ]
    ) {

        return MODULE_ALIASES[
            lowerValue
        ];

    }


    // -------------------------------------------------
    // CANONICAL MODULE
    // -------------------------------------------------

    const canonicalModule =
        Object.keys(
            SYSTEM_LOOKUP_FIELDS
        ).find(

            moduleName =>
                moduleName.toLowerCase() ===
                lowerValue

        );


    if (canonicalModule) {

        return canonicalModule;

    }


    // -------------------------------------------------
    // UNKNOWN MODULE
    // -------------------------------------------------

    return value;

};


// =====================================================
// GET SYSTEM LOOKUP FIELDS
// =====================================================

const getSystemLookupFields = (
    module
) => {

    const normalizedModule =
        normalizeModule(
            module
        );


    return (
        SYSTEM_LOOKUP_FIELDS[
            normalizedModule
        ] || []
    );

};


// =====================================================
// GET SYSTEM LOOKUP CATEGORIES
// =====================================================

const getSystemLookupCategories = (
    module
) => {

    return getSystemLookupFields(
        module
    ).map(

        field => ({

            field:
                field.field,

            category:
                field.category,

            label:
                field.label,

            multiple:
                field.multiple,

            ...(field.dependsOn
                ? {
                    dependsOn:
                        field.dependsOn
                }
                : {})

        })

    );

};


// =====================================================
// GET LOOKUP CATEGORY NAMES
// =====================================================

const getLookupCategoriesByModule = (
    module
) => {

    return getSystemLookupFields(
        module
    ).map(

        field =>
            field.category

    );

};


// =====================================================
// GET FIELD BY FIELD NAME
// =====================================================

const getSystemLookupField = (
    module,
    fieldName
) => {

    const normalizedModule =
        normalizeModule(
            module
        );


    const normalizedField =
        String(
            fieldName || ""
        )
            .trim();


    if (!normalizedField) {

        return null;

    }


    return getSystemLookupFields(
        normalizedModule
    ).find(

        field =>
            field.field ===
            normalizedField

    ) || null;

};


// =====================================================
// GET FIELD BY CATEGORY
// =====================================================

const getSystemLookupFieldByCategory = (
    module,
    category
) => {

    const normalizedModule =
        normalizeModule(
            module
        );


    const normalizedCategory =
        String(
            category || ""
        )
            .trim()
            .toLowerCase();


    if (!normalizedCategory) {

        return null;

    }


    return getSystemLookupFields(
        normalizedModule
    ).find(

        field =>
            field.category
                .trim()
                .toLowerCase() ===
            normalizedCategory

    ) || null;

};


// =====================================================
// CHECK SYSTEM LOOKUP FIELD
// =====================================================

const isSystemLookupField = (
    module,
    fieldName
) => {

    return Boolean(

        getSystemLookupField(
            module,
            fieldName
        )

    );

};


// =====================================================
// CHECK SYSTEM LOOKUP CATEGORY
// =====================================================

const isSystemLookupCategory = (
    module,
    category
) => {

    return Boolean(

        getSystemLookupFieldByCategory(
            module,
            category
        )

    );

};


// =====================================================
// GET CANONICAL MODULES
// =====================================================

const getSystemLookupModules = () => {

    return Object.keys(
        SYSTEM_LOOKUP_FIELDS
    );

};


// =====================================================
// CHECK SYSTEM LOOKUP MODULE
// =====================================================

const isSystemLookupModule = (
    module
) => {

    const normalizedModule =
        normalizeModule(
            module
        );


    return Object.prototype.hasOwnProperty.call(

        SYSTEM_LOOKUP_FIELDS,

        normalizedModule

    );

};


// =====================================================
// GET MODULE DEFINITION
// =====================================================

const getSystemLookupModuleDefinition = (
    module
) => {

    const normalizedModule =
        normalizeModule(
            module
        );


    if (
        !isSystemLookupModule(
            normalizedModule
        )
    ) {

        return null;

    }


    return {

        module:
            normalizedModule,

        fields:
            getSystemLookupFields(
                normalizedModule
            ),

        categories:
            getSystemLookupCategories(
                normalizedModule
            )

    };

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    SYSTEM_LOOKUP_FIELDS,

    MODULE_ALIASES,

    normalizeModule,

    getSystemLookupModules,

    getSystemLookupFields,

    getSystemLookupCategories,

    getLookupCategoriesByModule,

    getSystemLookupField,

    getSystemLookupFieldByCategory,

    isSystemLookupField,

    isSystemLookupCategory,

    isSystemLookupModule,

    getSystemLookupModuleDefinition

};