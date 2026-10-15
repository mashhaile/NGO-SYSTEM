// ==========================================================
// CUSTOM FIELD RESERVED KEYS
// ==========================================================
//
// Prevent custom-field keys from conflicting with real
// model properties.
//
// Supported modules:
// - Beneficiary
// - Enterprise
// - EnterpriseMember
// - Future modules
//
// Keys are normalized to lowercase before comparison.
// ==========================================================


// ==========================================================
// COMMON RESERVED KEYS
// ==========================================================

const commonReservedKeys = new Set([

    "_id",
    "id",
    "__v",

    "createdat",
    "updatedat",

    "organization",

    "createdby",
    "updatedby",

    "isdeleted",
    "deletedat",
    "deletedby",

    "customfields",

    "__proto__",
    "prototype",
    "constructor"

]);


// ==========================================================
// BENEFICIARY RESERVED KEYS
// ==========================================================

const beneficiaryReservedKeys = new Set([

    ...commonReservedKeys,

    "beneficiarynumber",

    "firstname",
    "middlename",
    "lastname",

    "gender",
    "dateofbirth",
    "age",

    "phone",
    "alternativephone",
    "email",

    "country",
    "region",
    "zone",
    "woreda",
    "kebele",
    "address",

    "educationlevel",
    "occupation",
    "maritalstatus",

    "ispwd",
    "disabilitytype",
    "vulnerablegroups",

    "documents",

    "status"

]);


// ==========================================================
// ENTERPRISE RESERVED KEYS
// ==========================================================

const enterpriseReservedKeys = new Set([

    ...commonReservedKeys,

    "enterprisenumber",

    "name",
    "description",

    "phone",
    "email",

    "address",

    "country",
    "region",
    "zone",
    "woreda",
    "kebele",

    "status"

]);


// ==========================================================
// ENTERPRISE MEMBER RESERVED KEYS
// ==========================================================

const enterpriseMemberReservedKeys = new Set([

    ...commonReservedKeys,

    "enterprise",
    "beneficiary",

    "role",

    "joineddate",
    "leftdate",

    "status"

]);


// ==========================================================
// DONOR RESERVED KEYS
// ==========================================================

const donorReservedKeys = new Set([

    ...commonReservedKeys,

    "donornumber",

    "firstname",
    "middlename",
    "lastname",

    "name",

    "phone",
    "alternativephone",
    "email",

    "address",

    "country",
    "region",
    "zone",
    "woreda",
    "kebele",

    "type",

    "status"

]);


// ==========================================================
// PROGRAM RESERVED KEYS
// ==========================================================

const programReservedKeys = new Set([

    ...commonReservedKeys,

    "programnumber",

    "name",
    "description",

    "startdate",
    "enddate",

    "status"

]);


// ==========================================================
// SERVICE DELIVERY RESERVED KEYS
// ==========================================================

const serviceDeliveryReservedKeys = new Set([

    ...commonReservedKeys,

    "beneficiary",
    "program",
    "service",

    "servicedate",

    "status"

]);


// ==========================================================
// USER RESERVED KEYS
// ==========================================================

const userReservedKeys = new Set([

    ...commonReservedKeys,

    "firstname",
    "middlename",
    "lastname",

    "username",

    "email",
    "phone",

    "password",
    "passwordhash",

    "role",

    "status"

]);


// ==========================================================
// RESERVED KEYS BY MODULE
// ==========================================================

const reservedKeysByModule = {

    Beneficiary:
        beneficiaryReservedKeys,

    Enterprise:
        enterpriseReservedKeys,

    EnterpriseMember:
        enterpriseMemberReservedKeys,

    Donor:
        donorReservedKeys,

    Program:
        programReservedKeys,

    ServiceDelivery:
        serviceDeliveryReservedKeys,

    User:
        userReservedKeys

};


// ==========================================================
// NORMALIZE KEY
// ==========================================================

const normalizeCustomFieldKey = (
    key
) => {

    return String(key || "")
        .trim()
        .toLowerCase();

};


// ==========================================================
// CHECK RESERVED KEY
// ==========================================================

const isReservedCustomFieldKey = (
    module,
    key
) => {

    const reservedKeys =
        reservedKeysByModule[module];


    // ------------------------------------------------------
    // Unknown module
    // ------------------------------------------------------

    if (!reservedKeys) {

        return false;

    }


    return reservedKeys.has(

        normalizeCustomFieldKey(
            key
        )

    );

};


// ==========================================================
// ASSERT KEY ALLOWED
// ==========================================================

const assertCustomFieldKeyAllowed = (
    module,
    key
) => {

    const normalizedKey =
        normalizeCustomFieldKey(
            key
        );


    if (
        isReservedCustomFieldKey(
            module,
            normalizedKey
        )
    ) {

        throw new Error(

            `Custom field key "${normalizedKey}" is reserved for the ${module} module.`

        );

    }

};


// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    isReservedCustomFieldKey,

    assertCustomFieldKeyAllowed

};