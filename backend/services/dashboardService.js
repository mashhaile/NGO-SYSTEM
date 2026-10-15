const Beneficiary = require("../models/Beneficiary");
const Program = require("../models/program");
const Donor = require("../models/donor");
const Donation = require("../models/donation");
const Enrollment = require("../models/enrollment");
const ServiceDelivery = require("../models/ServiceDelivery");


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
            gender: "Male"
        }),


        Beneficiary.countDocuments({
            ...organizationFilter,
            gender: "Female"
        }),


        Beneficiary.countDocuments({
            ...organizationFilter,

            gender: {
                $nin: [
                    "Male",
                    "Female"
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

        ServiceDelivery.countDocuments(
            organizationFilter
        ),


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

                                $eq: [

                                    {
                                        $toLower: {

                                            $ifNull: [

                                                "$$beneficiary.gender",

                                                ""

                                            ]

                                        }

                                    },

                                    "male"

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

                                $eq: [

                                    {
                                        $toLower: {

                                            $ifNull: [

                                                "$$beneficiary.gender",

                                                ""

                                            ]

                                        }

                                    },

                                    "female"

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

        const value =
            String(
                item._id || ""
            )
                .trim()
                .toLowerCase();


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