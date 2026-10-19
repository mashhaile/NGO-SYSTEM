const Beneficiary = require("../models/Beneficiary");
const Program = require("../models/program");
const Donor = require("../models/donor");
const Donation = require("../models/donation");
const Enrollment = require("../models/enrollment");
const ServiceDelivery = require("../models/ServiceDelivery");
const Lookup = require("../models/Lookup");

const {
    COUNTED_DELIVERY_FILTER
} = require("../constants/serviceDeliveryStatus");


// =====================================================
// GENDER LOOKUPS
// =====================================================
//
// Beneficiary.gender stores a Lookup id
// (Beneficiary / Gender). Classify each of the
// organization's gender lookups as male / female by
// code or value so counts can match by id.
//
// =====================================================

const classifyGender = (value) => {

    const normalized =
        String(value || "")
            .trim()
            .toLowerCase();

    if (["male", "m"].includes(normalized)) {
        return "male";
    }

    if (["female", "f"].includes(normalized)) {
        return "female";
    }

    return "other";

};


const getGenderIds = async (organizationId) => {

    const lookups =
        await Lookup.find({
            organization:
                organizationId,
            module:
                "Beneficiary",
            category:
                "Gender"
        })
            .select("_id code value")
            .lean();

    const ids = {
        male: [],
        female: []
    };

    const classById =
        new Map();

    lookups.forEach(lookup => {

        const genderClass =
            classifyGender(lookup.code) !== "other"
                ? classifyGender(lookup.code)
                : classifyGender(lookup.value);

        classById.set(
            String(lookup._id),
            genderClass
        );

        if (ids[genderClass]) {
            ids[genderClass].push(lookup._id);
        }

    });

    return {
        ...ids,
        classify: (genderValue) =>
            classById.get(String(genderValue)) ||
            classifyGender(genderValue)
    };

};


const getDashboard = async (organizationId) => {

    // =====================================================
    // VALIDATION
    // =====================================================

    if (!organizationId) {
        throw new Error("Organization ID is required");
    }


    // =====================================================
    // COMMON ORGANIZATION FILTER
    // =====================================================

    const organizationFilter = {
        organization: organizationId,
        isDeleted: false
    };

    const genderIds =
        await getGenderIds(
            organizationId
        );


    // =====================================================
    // BASIC DASHBOARD DATA
    // =====================================================

    const [

        totalBeneficiaries,

        activeBeneficiaries,

        maleBeneficiaries,

        femaleBeneficiaries,

        otherBeneficiaries,

        programs,

        activePrograms,

        donors,

        donations,

        totalDonation,

        services,

        enrollments,

        genderDistribution,

        beneficiariesByProgram

    ] = await Promise.all([


        // =================================================
        // BENEFICIARIES
        // =================================================

        Beneficiary.countDocuments(
            organizationFilter
        ),


        Beneficiary.countDocuments({
            ...organizationFilter,
            status: "Active"
        }),


        Beneficiary.countDocuments({
            ...organizationFilter,
            gender: {
                $in: genderIds.male
            }
        }),


        Beneficiary.countDocuments({
            ...organizationFilter,
            gender: {
                $in: genderIds.female
            }
        }),


        Beneficiary.countDocuments({
            ...organizationFilter,

            gender: {
                $nin: [
                    ...genderIds.male,
                    ...genderIds.female
                ]
            }
        }),


        // =================================================
        // PROGRAMS
        // =================================================

        Program.countDocuments(
            organizationFilter
        ),


        Program.countDocuments({
            ...organizationFilter,
            status: "Active"
        }),


        // =================================================
        // DONORS
        // =================================================

        Donor.countDocuments(
            organizationFilter
        ),


        // =================================================
        // DONATIONS
        // =================================================

        Donation.countDocuments(
            organizationFilter
        ),


        Donation.aggregate([

            {
                $match:
                    organizationFilter
            },

            {
                $group: {

                    _id: null,

                    total: {

                        $sum: {

                            $ifNull: [
                                "$amount",
                                0
                            ]

                        }

                    }

                }

            }

        ]),


        // =================================================
        // SERVICES
        // =================================================

        ServiceDelivery.countDocuments({
            ...organizationFilter,
            ...COUNTED_DELIVERY_FILTER
        }),


        // =================================================
        // ACTIVE ENROLLMENTS
        // =================================================

        Enrollment.countDocuments({

            ...organizationFilter,

            status: "Active"

        }),


        // =================================================
        // GLOBAL GENDER DISTRIBUTION
        // =================================================

        Beneficiary.aggregate([

            {
                $match:
                    organizationFilter
            },

            {
                $group: {

                    _id:
                        "$gender",

                    count: {
                        $sum: 1
                    }

                }

            }

        ]),


        // =================================================
        // BENEFICIARIES BY PROGRAM
        //
        // Program
        //    ↓
        // Enrollment
        //    ↓
        // Beneficiary
        //
        // This gives:
        // - total beneficiaries
        // - male
        // - female
        // - target
        // =================================================

        Program.aggregate([


            // =============================================
            // PROGRAMS
            // =============================================

            {
                $match: {

                    organization:
                        organizationId,

                    isDeleted:
                        false

                }

            },


            // =============================================
            // ENROLLMENTS
            // =============================================

            {
                $lookup: {

                    from:
                        "enrollments",

                    let: {

                        programId:
                            "$_id"

                    },

                    pipeline: [

                        {
                            $match: {

                                $expr: {

                                    $and: [

                                        {
                                            $eq: [
                                                "$program",
                                                "$$programId"
                                            ]
                                        },

                                        {
                                            $eq: [
                                                "$organization",
                                                organizationId
                                            ]
                                        },

                                        {
                                            $eq: [
                                                "$isDeleted",
                                                false
                                            ]
                                        }

                                    ]

                                }

                            }

                        }

                    ],

                    as:
                        "enrollments"

                }

            },


            // =============================================
            // GET BENEFICIARIES
            // =============================================

            {
                $lookup: {

                    from:
                        "beneficiaries",

                    let: {

                        beneficiaryIds:
                            "$enrollments.beneficiary"

                    },

                    pipeline: [

                        {
                            $match: {

                                $expr: {

                                    $and: [

                                        {
                                            $in: [

                                                "$_id",

                                                {
                                                    $ifNull: [

                                                        "$$beneficiaryIds",

                                                        []

                                                    ]

                                                }

                                            ]

                                        },

                                        {
                                            $eq: [

                                                "$organization",

                                                organizationId

                                            ]

                                        },

                                        {
                                            $eq: [

                                                "$isDeleted",

                                                false

                                            ]

                                        }

                                    ]

                                }

                            }

                        },

                        {
                            $project: {

                                _id: 1,

                                gender: 1

                            }

                        }

                    ],

                    as:
                        "beneficiaries"

                }

            },


            // =============================================
            // MALE BENEFICIARIES
            // =============================================

            {
                $addFields: {

                    maleBeneficiaries: {

                        $filter: {

                            input:
                                "$beneficiaries",

                            as:
                                "beneficiary",

                            cond: {

                                $in: [

                                    "$$beneficiary.gender",

                                    genderIds.male

                                ]

                            }

                        }

                    }

                }

            },


            // =============================================
            // FEMALE BENEFICIARIES
            // =============================================

            {
                $addFields: {

                    femaleBeneficiaries: {

                        $filter: {

                            input:
                                "$beneficiaries",

                            as:
                                "beneficiary",

                            cond: {

                                $in: [

                                    "$$beneficiary.gender",

                                    genderIds.female

                                ]

                            }

                        }

                    }

                }

            },


            // =============================================
            // COUNTS
            // =============================================

            {
                $addFields: {

                    beneficiaries: {

                        $size:
                            "$beneficiaries"

                    },

                    male: {

                        $size:
                            "$maleBeneficiaries"

                    },

                    female: {

                        $size:
                            "$femaleBeneficiaries"

                    }

                }

            },


            // =============================================
            // RETURN CLEAN DATA
            // =============================================

            {
                $project: {

                    _id: 0,

                    programId:
                        "$_id",

                    programName:
                        "$name",

                    target: {

                        $ifNull: [

                            "$targetBeneficiaries",

                            0

                        ]

                    },

                    beneficiaries: 1,

                    male: 1,

                    female: 1

                }

            },


            // =============================================
            // SORT
            // =============================================

            {
                $sort: {

                    beneficiaries:
                        -1,

                    programName:
                        1

                }

            }

        ])

    ]);


    // =====================================================
    // NORMALIZE GLOBAL GENDER DATA
    // =====================================================

    const gender = {

        male: 0,

        female: 0,

        other: 0

    };


    genderDistribution.forEach(item => {

        // _id is a Gender lookup id (or legacy text)

        const value =
            genderIds.classify(
                item._id
            );


        if (value === "male") {

            gender.male +=
                Number(
                    item.count || 0
                );

        }

        else if (value === "female") {

            gender.female +=
                Number(
                    item.count || 0
                );

        }

        else {

            gender.other +=
                Number(
                    item.count || 0
                );

        }

    });


    // =====================================================
    // TOTAL FUNDING
    // =====================================================

    const totalDonationAmount =
        totalDonation.length > 0

            ? Number(
                totalDonation[0].total || 0
            )

            : 0;


    // =====================================================
    // FINAL DASHBOARD RESPONSE
    // =====================================================

    return {

        title:
            "NGO Management Dashboard",


        // =================================================
        // SUMMARY
        // =================================================

        summary: {

            totalBeneficiaries,

            activeBeneficiaries,

            totalPrograms:
                programs,

            activePrograms,

            totalDonors:
                donors,

            totalDonations:
                donations,

            totalFunding:
                totalDonationAmount,

            totalServices:
                services,

            activeEnrollments:
                enrollments

        },


        // =================================================
        // GENDER DISTRIBUTION
        // =================================================

        genderDistribution: {

            male:
                gender.male,

            female:
                gender.female,

            other:
                gender.other,

            total:

                gender.male +

                gender.female +

                gender.other

        },


        // =================================================
        // CHARTS
        // =================================================

        charts: {

            fundingTrend: [],

            serviceTrend: [],

            beneficiaryTrend: [],

            beneficiariesByProgram

        },


        // =================================================
        // DASHBOARD META
        // =================================================

        meta: {

            organizationId,

            generatedAt:
                new Date()

        }

    };

};


module.exports = {
    getDashboard
};