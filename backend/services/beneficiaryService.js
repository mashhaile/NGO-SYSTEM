const generateSequence =
    require("../utils/generateSequence");

const queryHelper =
    require("../utils/queryHelper");

const resolveLookup =
    require("../utils/lookupResolver");

const {
    processCustomFields
} =
    require("../utils/customFieldProcessor");

const Beneficiary =
    require("../models/Beneficiary");

const {
    checkResourceLimit
} =
    require("../services/subscriptionService");


// ==========================================================
// BENEFICIARY LOOKUP CATEGORIES
// ==========================================================

const BENEFICIARY_LOOKUP_CATEGORIES = {

    gender:
        "Gender",

    educationLevel:
        "EducationLevel",

    occupation:
        "Occupation",

    maritalStatus:
        "MaritalStatus",

    disabilityType:
        "DisabilityType",

    vulnerableGroups:
        "VulnerableGroup"

};


// ==========================================================
// LOOKUP MODULE
// ==========================================================

const BENEFICIARY_LOOKUP_MODULE =
    "Beneficiary";


// ==========================================================
// CALCULATE AGE FROM DATE OF BIRTH
// ==========================================================
//
// Date of birth is the source of truth.
//
// Age is NEVER trusted from the client/import file.
//
// ==========================================================

const calculateAge = (dateOfBirth) => {

    if (
        dateOfBirth === undefined ||
        dateOfBirth === null ||
        dateOfBirth === ""
    ) {

        return null;

    }


    const dob =
        new Date(dateOfBirth);


    if (
        Number.isNaN(
            dob.getTime()
        )
    ) {

        throw new Error(
            "Invalid date of birth"
        );

    }


    const today =
        new Date();


    let age =
        today.getFullYear() -
        dob.getFullYear();


    const monthDifference =
        today.getMonth() -
        dob.getMonth();


    // ------------------------------------------------------
    // Birthday has not occurred yet this year.
    // ------------------------------------------------------

    if (
        monthDifference < 0 ||
        (
            monthDifference === 0 &&
            today.getDate() < dob.getDate()
        )
    ) {

        age--;

    }


    // ------------------------------------------------------
    // FUTURE DATE
    // ------------------------------------------------------

    if (
        age < 0
    ) {

        throw new Error(
            "Date of birth cannot be in the future"
        );

    }


    // ------------------------------------------------------
    // MAXIMUM AGE
    // ------------------------------------------------------

    if (
        age > 120
    ) {

        throw new Error(
            "Beneficiary age cannot exceed 120 years"
        );

    }


    return age;

};


// ==========================================================
// RESOLVE OPTIONAL LOOKUP
// ==========================================================
//
// Accepts:
//
// - Lookup ObjectId
// - Lookup value
//
// ==========================================================

const resolveOptionalLookup = async (
    organizationId,
    category,
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    const resolved =
        await resolveLookup(

            organizationId,

            BENEFICIARY_LOOKUP_MODULE,

            category,

            value

        );


    return resolved;

};


// ==========================================================
// PROCESS VULNERABILITY GROUPS
// ==========================================================

const processVulnerableGroups = async (
    groups = [],
    organizationId
) => {

    if (
        !Array.isArray(groups)
    ) {

        return [];

    }


    const result = [];


    for (
        const group
        of groups
    ) {

        if (
            group === undefined ||
            group === null ||
            group === ""
        ) {

            continue;

        }


        const id =
            await resolveOptionalLookup(

                organizationId,

                BENEFICIARY_LOOKUP_CATEGORIES
                    .vulnerableGroups,

                group

            );


        if (id) {

            result.push(id);

        }

    }


    // ------------------------------------------------------
    // REMOVE DUPLICATES
    // ------------------------------------------------------

    const uniqueIds = [];

    const seen =
        new Set();


    for (
        const id
        of result
    ) {

        const stringId =
            id.toString();


        if (
            !seen.has(stringId)
        ) {

            seen.add(
                stringId
            );

            uniqueIds.push(
                id
            );

        }

    }


    return uniqueIds;

};


// ==========================================================
// PROCESS PWD
// ==========================================================

const processPWD = async (
    isPWD,
    disabilityType,
    organizationId
) => {

    // ------------------------------------------------------
    // NOT PWD
    // ------------------------------------------------------

    if (
        isPWD !== true
    ) {

        return {

            isPWD:
                false,

            disabilityType:
                null

        };

    }


    // ------------------------------------------------------
    // PWD REQUIRES DISABILITY TYPE
    // ------------------------------------------------------

    if (
        disabilityType === undefined ||
        disabilityType === null ||
        disabilityType === ""
    ) {

        throw new Error(
            "Disability type is required when beneficiary is PWD"
        );

    }


    const resolvedDisabilityType =
        await resolveOptionalLookup(

            organizationId,

            BENEFICIARY_LOOKUP_CATEGORIES
                .disabilityType,

            disabilityType

        );


    if (
        !resolvedDisabilityType
    ) {

        throw new Error(
            "Invalid Beneficiary/DisabilityType lookup."
        );

    }


    return {

        isPWD:
            true,

        disabilityType:
            resolvedDisabilityType

    };

};


// ==========================================================
// CREATE BENEFICIARY
// ==========================================================

const createBeneficiary = async (
    data,
    organizationId,
    userId
) => {

    await checkResourceLimit(
        organizationId,
        "beneficiaries"
    );


    // ------------------------------------------------------
    // PHONE DUPLICATE CHECK
    // ------------------------------------------------------

    if (
        data.phone
    ) {

        const existingBeneficiary =
            await Beneficiary.findOne({

                organization:
                    organizationId,

                phone:
                    data.phone,

                isDeleted:
                    false

            });


        if (
            existingBeneficiary
        ) {

            throw new Error(
                "Phone number already exists"
            );

        }

    }


    // ------------------------------------------------------
    // SEPARATE CUSTOM FIELDS
    // ------------------------------------------------------

    const {

        customFields = [],

        ...beneficiaryData

    } = data;


    // ------------------------------------------------------
    // GENERATE BENEFICIARY NUMBER
    // ------------------------------------------------------

    const beneficiaryNumber =
        await generateSequence(

            "Beneficiary",

            "BEN",

            organizationId

        );


    // ------------------------------------------------------
    // CALCULATE AGE
    // ------------------------------------------------------
    //
    // Age supplied by client is ignored.
    //
    // dateOfBirth is the source of truth.
    //
    // ------------------------------------------------------

    const calculatedAge =
        calculateAge(
            beneficiaryData.dateOfBirth
        );


    // ------------------------------------------------------
    // PROCESS CUSTOM FIELDS
    // ------------------------------------------------------

    const savedCustomFields =
        await processCustomFields(

            customFields,

            organizationId,

            true,

            "Beneficiary"

        );


    // ------------------------------------------------------
    // GENDER
    // ------------------------------------------------------

    const gender =
        await resolveOptionalLookup(

            organizationId,

            BENEFICIARY_LOOKUP_CATEGORIES
                .gender,

            beneficiaryData.gender

        );


    // ------------------------------------------------------
    // EDUCATION LEVEL
    // ------------------------------------------------------

    const educationLevel =
        await resolveOptionalLookup(

            organizationId,

            BENEFICIARY_LOOKUP_CATEGORIES
                .educationLevel,

            beneficiaryData.educationLevel

        );


    // ------------------------------------------------------
    // OCCUPATION
    // ------------------------------------------------------

    const occupation =
        await resolveOptionalLookup(

            organizationId,

            BENEFICIARY_LOOKUP_CATEGORIES
                .occupation,

            beneficiaryData.occupation

        );


    // ------------------------------------------------------
    // MARITAL STATUS
    // ------------------------------------------------------

    const maritalStatus =
        await resolveOptionalLookup(

            organizationId,

            BENEFICIARY_LOOKUP_CATEGORIES
                .maritalStatus,

            beneficiaryData.maritalStatus

        );


    // ------------------------------------------------------
    // VULNERABILITY GROUPS
    // ------------------------------------------------------

    const resolvedVulnerableGroups =
        await processVulnerableGroups(

            beneficiaryData.vulnerableGroups,

            organizationId

        );


    // ------------------------------------------------------
    // PWD
    // ------------------------------------------------------

    const pwdData =
        await processPWD(

            beneficiaryData.isPWD,

            beneficiaryData.disabilityType,

            organizationId

        );


    // ------------------------------------------------------
    // CREATE
    // ------------------------------------------------------

    const beneficiary =
        await Beneficiary.create({

            ...beneficiaryData,

            beneficiaryNumber,

            organization:
                organizationId,

            createdBy:
                userId,

            // ------------------------------------------------
            // AGE IS ALWAYS CALCULATED
            // ------------------------------------------------

            age:
                calculatedAge,

            gender,

            educationLevel,

            occupation,

            maritalStatus,

            isPWD:
                pwdData.isPWD,

            disabilityType:
                pwdData.disabilityType,

            vulnerableGroups:
                resolvedVulnerableGroups,

            customFields:
                savedCustomFields

        });


    return beneficiary;

};


// ==========================================================
// GET ALL BENEFICIARIES
// ==========================================================

const getBeneficiaries = async (
    organizationId,
    reqQuery
) => {

    return await queryHelper({

        model:
            Beneficiary,

        organizationId,

        reqQuery,

        searchableFields: [

            "beneficiaryNumber",

            "firstName",

            "middleName",

            "lastName",

            "phone",

            "zone",

            "woreda"

        ],

        populate: [

            {
                path:
                    "gender",

                select:
                    "value code category active"
            },

            {
                path:
                    "educationLevel",

                select:
                    "value code category active"
            },

            {
                path:
                    "occupation",

                select:
                    "value code category active"
            },

            {
                path:
                    "maritalStatus",

                select:
                    "value code category active"
            },

            {
                path:
                    "disabilityType",

                select:
                    "value code category active"
            },

            {
                path:
                    "vulnerableGroups",

                select:
                    "value code category active"
            },

            {
                path:
                    "customFields.fieldId",

                select:
                    "label key type options required placeholder validation active module"
            }

        ],

        statusConfig: {

            enabled:
                true,

            type:
                "string"

        }

    });

};


// ==========================================================
// GET BENEFICIARY BY ID
// ==========================================================

const getBeneficiaryById = async (
    id,
    organizationId
) => {

    const beneficiary =
        await Beneficiary.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        })

        .populate(
            "gender",
            "value code category active"
        )

        .populate(
            "educationLevel",
            "value code category active"
        )

        .populate(
            "occupation",
            "value code category active"
        )

        .populate(
            "maritalStatus",
            "value code category active"
        )

        .populate(
            "disabilityType",
            "value code category active"
        )

        .populate(
            "vulnerableGroups",
            "value code category active"
        )

        .populate({

            path:
                "customFields.fieldId",

            select:
                "label key type options required placeholder validation active module"

        });


    if (
        !beneficiary
    ) {

        throw new Error(
            "Beneficiary not found"
        );

    }


    return beneficiary;

};


// ==========================================================
// UPDATE BENEFICIARY
// ==========================================================

const updateBeneficiary = async (
    id,
    data,
    organizationId,
    userId
) => {

    // ------------------------------------------------------
    // VERIFY BENEFICIARY
    // ------------------------------------------------------

    const existingBeneficiary =
        await Beneficiary.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (
        !existingBeneficiary
    ) {

        throw new Error(
            "Beneficiary not found"
        );

    }


    const hasField =
        fieldName =>
            Object.prototype.hasOwnProperty.call(
                data,
                fieldName
            );


    const updatedData = {

        updatedBy:
            userId

    };


    // ------------------------------------------------------
    // EDITABLE SCALAR FIELDS
    // ------------------------------------------------------
    //
    // IMPORTANT:
    //
    // "age" is intentionally NOT here.
    //
    // Age is calculated from dateOfBirth.
    //
    // ------------------------------------------------------

    const editableScalarFields = [

        "firstName",

        "middleName",

        "lastName",

        "dateOfBirth",

        "phone",

        "alternativePhone",

        "email",

        "country",

        "region",

        "zone",

        "woreda",

        "kebele",

        "address",

        "documents",

        "status"

    ];


    editableScalarFields.forEach(
        fieldName => {

            if (
                hasField(fieldName)
            ) {

                updatedData[fieldName] =
                    data[fieldName];

            }

        }
    );


    // ------------------------------------------------------
    // CALCULATE AGE
    // ------------------------------------------------------
    //
    // If DOB is being updated, use the new DOB.
    //
    // Otherwise use the existing DOB.
    //
    // This keeps age synchronized.
    //
    // ------------------------------------------------------

    const finalDateOfBirth =
        hasField("dateOfBirth")
            ? data.dateOfBirth
            : existingBeneficiary.dateOfBirth;


    updatedData.age =
        calculateAge(
            finalDateOfBirth
        );


    // ------------------------------------------------------
    // GENDER
    // ------------------------------------------------------

    if (
        hasField("gender")
    ) {

        updatedData.gender =
            await resolveOptionalLookup(

                organizationId,

                BENEFICIARY_LOOKUP_CATEGORIES
                    .gender,

                data.gender

            );

    }


    // ------------------------------------------------------
    // PHONE DUPLICATE CHECK
    // ------------------------------------------------------

    if (
        hasField("phone") &&
        data.phone
    ) {

        const duplicate =
            await Beneficiary.findOne({

                organization:
                    organizationId,

                phone:
                    data.phone,

                isDeleted:
                    false,

                _id: {
                    $ne:
                        id
                }

            });


        if (
            duplicate
        ) {

            throw new Error(
                "Phone number already exists"
            );

        }

    }


    // ------------------------------------------------------
    // CUSTOM FIELDS
    // ------------------------------------------------------

    if (
        hasField("customFields")
    ) {

        updatedData.customFields =
            await processCustomFields(

                data.customFields,

                organizationId,

                false,

                "Beneficiary"

            );

    }


    // ------------------------------------------------------
    // EDUCATION LEVEL
    // ------------------------------------------------------

    if (
        hasField("educationLevel")
    ) {

        updatedData.educationLevel =
            await resolveOptionalLookup(

                organizationId,

                BENEFICIARY_LOOKUP_CATEGORIES
                    .educationLevel,

                data.educationLevel

            );

    }


    // ------------------------------------------------------
    // OCCUPATION
    // ------------------------------------------------------

    if (
        hasField("occupation")
    ) {

        updatedData.occupation =
            await resolveOptionalLookup(

                organizationId,

                BENEFICIARY_LOOKUP_CATEGORIES
                    .occupation,

                data.occupation

            );

    }


    // ------------------------------------------------------
    // MARITAL STATUS
    // ------------------------------------------------------

    if (
        hasField("maritalStatus")
    ) {

        updatedData.maritalStatus =
            await resolveOptionalLookup(

                organizationId,

                BENEFICIARY_LOOKUP_CATEGORIES
                    .maritalStatus,

                data.maritalStatus

            );

    }


    // ------------------------------------------------------
    // PWD
    // ------------------------------------------------------

    const hasIsPWD =
        hasField("isPWD");

    const hasDisabilityType =
        hasField("disabilityType");


    if (
        hasIsPWD ||
        hasDisabilityType
    ) {

        const intendedIsPWD =
            hasIsPWD
                ? data.isPWD
                : existingBeneficiary.isPWD;


        // --------------------------------------------------
        // NOT PWD
        // --------------------------------------------------

        if (
            !intendedIsPWD
        ) {

            if (
                hasDisabilityType &&
                data.disabilityType !== null &&
                data.disabilityType !== ""
            ) {

                throw new Error(
                    "Disability type cannot be set when beneficiary is not PWD"
                );

            }


            updatedData.isPWD =
                false;

            updatedData.disabilityType =
                null;

        }


        // --------------------------------------------------
        // PWD + NEW DISABILITY TYPE
        // --------------------------------------------------

        else if (
            hasDisabilityType
        ) {

            const pwdData =
                await processPWD(

                    true,

                    data.disabilityType,

                    organizationId

                );


            updatedData.isPWD =
                pwdData.isPWD;

            updatedData.disabilityType =
                pwdData.disabilityType;

        }


        // --------------------------------------------------
        // PWD + EXISTING DISABILITY TYPE
        // --------------------------------------------------

        else if (
            existingBeneficiary.disabilityType
        ) {

            updatedData.isPWD =
                true;

            updatedData.disabilityType =
                existingBeneficiary.disabilityType;

        }


        // --------------------------------------------------
        // PWD WITHOUT DISABILITY TYPE
        // --------------------------------------------------

        else {

            throw new Error(
                "Disability type is required when beneficiary is PWD"
            );

        }

    }


    // ------------------------------------------------------
    // VULNERABILITY GROUPS
    // ------------------------------------------------------

    if (
        hasField("vulnerableGroups")
    ) {

        updatedData.vulnerableGroups =
            await processVulnerableGroups(

                data.vulnerableGroups,

                organizationId

            );

    }


    // ------------------------------------------------------
    // UPDATE
    // ------------------------------------------------------

    const beneficiary =
        await Beneficiary.findOneAndUpdate(

            {

                _id:
                    id,

                organization:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set:
                    updatedData

            },

            {

                new:
                    true,

                runValidators:
                    true

            }

        );


    if (
        !beneficiary
    ) {

        throw new Error(
            "Beneficiary not found"
        );

    }


    return beneficiary;

};


// ==========================================================
// DELETE BENEFICIARY
// ==========================================================

const deleteBeneficiary = async (
    id,
    organizationId,
    userId
) => {

    const beneficiary =
        await Beneficiary.findOneAndUpdate(

            {

                _id:
                    id,

                organization:
                    organizationId,

                isDeleted:
                    false

            },

            {

                $set: {

                    isDeleted:
                        true,

                    deletedAt:
                        new Date(),

                    deletedBy:
                        userId

                }

            },

            {

                new:
                    true

            }

        );


    if (
        !beneficiary
    ) {

        throw new Error(
            "Beneficiary not found"
        );

    }


    return beneficiary;

};


// ==========================================================
// BENEFICIARY LOOKUP
// ==========================================================
//
// Optional program filter.
//
// Program
//    ↓
// Enrollment
//    ↓
// Beneficiary
//
// ==========================================================

const getBeneficiaryLookup = async (
    organizationId,
    programId = ""
) => {

    const query = {

        organization:
            organizationId,

        isDeleted:
            false,

        status:
            "Active"

    };


    // ------------------------------------------------------
    // FILTER BY PROGRAM THROUGH ENROLLMENT
    // ------------------------------------------------------

    if (programId) {

        const Enrollment =
            require("../models/enrollment");


        const enrollments =
            await Enrollment.find({

                organization:
                    organizationId,

                program:
                    programId,

                isDeleted:
                    false

            })
            .select(
                "beneficiary"
            );


        const beneficiaryIds =
            enrollments.map(
                enrollment =>
                    enrollment.beneficiary
            );


        if (
            beneficiaryIds.length === 0
        ) {

            return [];

        }


        query._id = {

            $in:
                beneficiaryIds

        };

    }


    return await Beneficiary.find(

        query,

        {

            beneficiaryNumber:
                1,

            firstName:
                1,

            middleName:
                1,

            lastName:
                1,

            phone:
                1

        }

    )
    .sort({

        firstName:
            1

    });

};


// ==========================================================
// EXPORT
// ==========================================================

module.exports = {

    createBeneficiary,

    getBeneficiaries,

    getBeneficiaryById,

    updateBeneficiary,

    deleteBeneficiary,

    getBeneficiaryLookup,

    // CustomField remains independent.
    processCustomFields

};