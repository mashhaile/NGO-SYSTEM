const Beneficiary = require("../../models/Beneficiary");
const Program = require("../../models/program");
const Donor = require("../../models/donor");
const Donation = require("../../models/donation");
const ServiceDelivery = require("../../models/ServiceDelivery");
const Enrollment = require("../../models/enrollment");



const generate = async (
    filters = {},
    context = {}
) => {

    const {
        organizationId
    } = context;


    // =====================================================
    // VALIDATION
    // =====================================================

    if (!organizationId) {

        throw new Error(
            "Organization ID is required"
        );

    }


    // =====================================================
    // BASIC COUNTS
    // =====================================================

    const [

        totalBeneficiaries,
        activeBeneficiaries,

        totalPrograms,
        activePrograms,
        completedPrograms,
        plannedPrograms,
        suspendedPrograms,
        cancelledPrograms,

        totalDonors,

        totalServices,

        totalEnrollments,
        activeEnrollments

    ] = await Promise.all([


        Beneficiary.countDocuments({

            organization: organizationId,

            isDeleted: false

        }),


        Beneficiary.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Active"

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Active"

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Completed"

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Planned"

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Suspended"

        }),


        Program.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Cancelled"

        }),


        Donor.countDocuments({

            organization: organizationId,

            isDeleted: false

        }),


        ServiceDelivery.countDocuments({

            organization: organizationId,

            isDeleted: false

        }),


        Enrollment.countDocuments({

            organization: organizationId,

            isDeleted: false

        }),


        Enrollment.countDocuments({

            organization: organizationId,

            isDeleted: false,

            status: "Active"

        })

    ]);



    // =====================================================
    // OVERALL GENDER DISTRIBUTION
    // =====================================================

    const genderAggregation =
        await Beneficiary.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false

                }

            },

            // =============================================
            // RESOLVE GENDER LOOKUP
            // =============================================

            {
                $lookup: {

                    from: "lookups",

                    localField: "gender",

                    foreignField: "_id",

                    as: "genderLookup"

                }

            },

            {
                $unwind: {

                    path: "$genderLookup",

                    preserveNullAndEmptyArrays: true

                }

            },

            {
                $group: {

                    _id: {

                        $toLower: {

                            $trim: {

                                input: {

                                    $convert: {

                                        input:
                                            "$genderLookup.value",

                                        to: "string",

                                        onError: "",

                                        onNull: ""

                                    }

                                }

                            }

                        }

                    },

                    count: {

                        $sum: 1

                    }

                }

            }

        ]);



    let male = 0;

    let female = 0;



    genderAggregation.forEach(item => {

        const gender =
            String(
                item._id || ""
            )
                .trim()
                .toLowerCase();


        if (gender === "male") {

            male += Number(
                item.count || 0
            );

        }


        if (gender === "female") {

            female += Number(
                item.count || 0
            );

        }

    });



    const genderTotal =
        male + female;



    // =====================================================
    // FUNDING TOTAL
    // =====================================================

    const fundingAggregation =
        await Donation.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false

                }

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

        ]);



    const totalFunding =
        fundingAggregation.length > 0

            ? Number(
                fundingAggregation[0].total || 0
            )

            : 0;



    // =====================================================
    // SERVICE VALUE
    // =====================================================

    const serviceValueAggregation =
        await ServiceDelivery.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false

                }

            },

            {
                $group: {

                    _id: null,

                    total: {

                        $sum: {

                            $ifNull: [
                                "$totalAmount",
                                0
                            ]

                        }

                    }

                }

            }

        ]);



    const totalServiceValue =
        serviceValueAggregation.length > 0

            ? Number(
                serviceValueAggregation[0].total || 0
            )

            : 0;



    // =====================================================
    // PROGRAM BUDGET
    // =====================================================

    const programBudgetAggregation =
        await Program.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false

                }

            },

            {
                $group: {

                    _id: null,

                    totalBudget: {

                        $sum: {

                            $ifNull: [
                                "$budget",
                                0
                            ]

                        }

                    },

                    targetBeneficiaries: {

                        $sum: {

                            $ifNull: [
                                "$targetBeneficiaries",
                                0
                            ]

                        }

                    }

                }

            }

        ]);



    const totalProgramBudget =
        programBudgetAggregation.length > 0

            ? Number(
                programBudgetAggregation[0]
                    .totalBudget || 0
            )

            : 0;



    const totalTargetBeneficiaries =
        programBudgetAggregation.length > 0

            ? Number(
                programBudgetAggregation[0]
                    .targetBeneficiaries || 0
            )

            : 0;



    // =====================================================
    // PROGRAM PERFORMANCE
    //
    // Program
    //    ↓
    // Enrollment
    //    ↓
    // Beneficiary
    //
    // Program
    //    ↓
    // ServiceDelivery
    // =====================================================

    const programPerformance =
        await Program.aggregate([

            // =================================================
            // PROGRAMS
            // =================================================

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false

                }

            },


            // =================================================
            // ENROLLMENTS
            // =================================================

            {
                $lookup: {

                    from: "enrollments",

                    let: {
                        programId: "$_id"
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

                        },

                        {
                            $project: {

                                _id: 1,

                                beneficiary: 1,

                                status: 1

                            }

                        }

                    ],

                    as: "enrollments"

                }

            },


            // =================================================
            // BENEFICIARIES
            //
            // IMPORTANT:
            // Gender is a Lookup ObjectId.
            //
            // We resolve the Lookup here before using
            // $trim / $toLower.
            // =================================================

            {
                $lookup: {

                    from: "beneficiaries",

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


                        // =====================================
                        // RESOLVE BENEFICIARY GENDER LOOKUP
                        // =====================================

                        {
                            $lookup: {

                                from: "lookups",

                                localField: "gender",

                                foreignField: "_id",

                                as: "genderLookup"

                            }

                        },


                        {
                            $unwind: {

                                path: "$genderLookup",

                                preserveNullAndEmptyArrays: true

                            }

                        },


                        {
                            $project: {

                                _id: 1,

                                gender: {

                                    $convert: {

                                        input:
                                            "$genderLookup.value",

                                        to: "string",

                                        onError: "",

                                        onNull: ""

                                    }

                                }

                            }

                        }

                    ],

                    as:
                        "programBeneficiaries"

                }

            },


            // =================================================
            // SERVICE DELIVERIES
            // =================================================

            {
                $lookup: {

                    from: "servicedeliveries",

                    let: {
                        programId: "$_id"
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

                        },

                        {
                            $project: {

                                totalAmount: 1

                            }

                        }

                    ],

                    as:
                        "services"

                }

            },


            // =================================================
            // PROGRAM METRICS
            // =================================================

            {
                $addFields: {

                    // -----------------------------------------
                    // TOTAL ENROLLMENTS
                    // -----------------------------------------

                    totalEnrollments: {

                        $size:
                            "$enrollments"

                    },


                    // -----------------------------------------
                    // ACTIVE ENROLLMENTS
                    // -----------------------------------------

                    activeEnrollments: {

                        $size: {

                            $filter: {

                                input:
                                    "$enrollments",

                                as:
                                    "enrollment",

                                cond: {

                                    $eq: [

                                        "$$enrollment.status",

                                        "Active"

                                    ]

                                }

                            }

                        }

                    },


                    // -----------------------------------------
                    // UNIQUE BENEFICIARIES
                    // -----------------------------------------

                    beneficiariesServed: {

                        $size: {

                            $setUnion: [

                                {

                                    $ifNull: [

                                        "$enrollments.beneficiary",

                                        []

                                    ]

                                },

                                []

                            ]

                        }

                    },


                    // -----------------------------------------
                    // MALE BENEFICIARIES
                    // -----------------------------------------

                    male: {

                        $size: {

                            $filter: {

                                input:
                                    "$programBeneficiaries",

                                as:
                                    "beneficiary",

                                cond: {

                                    $eq: [

                                        {

                                            $toLower: {

                                                $trim: {

                                                    input: {

                                                        $convert: {

                                                            input:
                                                                "$$beneficiary.gender",

                                                            to: "string",

                                                            onError: "",

                                                            onNull: ""

                                                        }

                                                    }

                                                }

                                            }

                                        },

                                        "male"

                                    ]

                                }

                            }

                        }

                    },


                    // -----------------------------------------
                    // FEMALE BENEFICIARIES
                    // -----------------------------------------

                    female: {

                        $size: {

                            $filter: {

                                input:
                                    "$programBeneficiaries",

                                as:
                                    "beneficiary",

                                cond: {

                                    $eq: [

                                        {

                                            $toLower: {

                                                $trim: {

                                                    input: {

                                                        $convert: {

                                                            input:
                                                                "$$beneficiary.gender",

                                                            to: "string",

                                                            onError: "",

                                                            onNull: ""

                                                        }

                                                    }

                                                }

                                            }

                                        },

                                        "female"

                                    ]

                                }

                            }

                        }

                    },


                    // -----------------------------------------
                    // SERVICES
                    // -----------------------------------------

                    totalServices: {

                        $size:
                            "$services"

                    },


                    // -----------------------------------------
                    // SERVICE VALUE
                    // -----------------------------------------

                    serviceValue: {

                        $sum:
                            "$services.totalAmount"

                    }

                }

            },


            // =================================================
            // PERFORMANCE RATE
            // =================================================

            {
                $addFields: {

                    performanceRate: {

                        $cond: [

                            {

                                $gt: [

                                    {

                                        $ifNull: [

                                            "$targetBeneficiaries",

                                            0

                                        ]

                                    },

                                    0

                                ]

                            },

                            {

                                $multiply: [

                                    {

                                        $divide: [

                                            "$beneficiariesServed",

                                            "$targetBeneficiaries"

                                        ]

                                    },

                                    100

                                ]

                            },

                            0

                        ]

                    }

                }

            },


            // =================================================
            // RESPONSE
            // =================================================

            {
                $project: {

                    _id: 0,

                    programId:
                        "$_id",

                    programCode: 1,

                    name: 1,

                    category: 1,

                    status: 1,

                    budget: 1,

                    targetBeneficiaries: 1,

                    startDate: 1,

                    endDate: 1,

                    totalEnrollments: 1,

                    activeEnrollments: 1,

                    beneficiariesServed: 1,

                    male: 1,

                    female: 1,

                    totalServices: 1,

                    serviceValue: 1,

                    performanceRate: 1

                }

            },


            // =================================================
            // SORT
            // =================================================

            {
                $sort: {

                    beneficiariesServed: -1,

                    totalServices: -1,

                    serviceValue: -1,

                    name: 1

                }

            }

        ]);



    // =====================================================
    // BENEFICIARIES BY PROGRAM
    // =====================================================

    const beneficiariesByProgram =
        programPerformance.map(program => ({

            programId:
                program.programId,

            programCode:
                program.programCode,

            programName:
                program.name ||
                "Unnamed Program",

            beneficiaries:
                Number(
                    program.beneficiariesServed || 0
                ),

            male:
                Number(
                    program.male || 0
                ),

            female:
                Number(
                    program.female || 0
                ),

            target:
                Number(
                    program.targetBeneficiaries || 0
                ),

            performanceRate:
                Number(
                    program.performanceRate || 0
                ),

            status:
                program.status

        }));



    // =====================================================
    // FUNDING TREND
    // =====================================================

    const monthlyFunding =
        await Donation.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false,

                    donationDate: {

                        $exists: true,

                        $ne: null

                    }

                }

            },

            {
                $group: {

                    _id: {

                        year: {
                            $year:
                                "$donationDate"
                        },

                        month: {
                            $month:
                                "$donationDate"
                        }

                    },

                    amount: {

                        $sum: {

                            $ifNull: [

                                "$amount",

                                0

                            ]

                        }

                    }

                }

            },

            {
                $sort: {

                    "_id.year": 1,

                    "_id.month": 1

                }

            }

        ]);



    const fundingTrend =
        monthlyFunding.map(item => ({

            month:
                `${item._id.month}/${item._id.year}`,

            amount:
                Number(
                    item.amount || 0
                )

        }));



    // =====================================================
    // SERVICE TREND
    // =====================================================

    const monthlyServices =
        await ServiceDelivery.aggregate([

            {
                $match: {

                    organization: organizationId,

                    isDeleted: false,

                    deliveryDate: {

                        $exists: true,

                        $ne: null

                    }

                }

            },

            {
                $group: {

                    _id: {

                        year: {
                            $year:
                                "$deliveryDate"
                        },

                        month: {
                            $month:
                                "$deliveryDate"
                        }

                    },

                    services: {

                        $sum: 1

                    },

                    value: {

                        $sum: {

                            $ifNull: [

                                "$totalAmount",

                                0

                            ]

                        }

                    }

                }

            },

            {
                $sort: {

                    "_id.year": 1,

                    "_id.month": 1

                }

            }

        ]);



    const serviceTrend =
        monthlyServices.map(item => ({

            month:
                `${item._id.month}/${item._id.year}`,

            services:
                Number(
                    item.services || 0
                ),

            value:
                Number(
                    item.value || 0
                )

        }));



    // =====================================================
    // RECENT ACTIVITY
    // =====================================================

    const recentBeneficiaries =
        await Beneficiary.find({

            organization: organizationId,

            isDeleted: false

        })

            .sort({

                createdAt: -1

            })

            .limit(5)

            .select(

                "firstName middleName lastName createdAt"

            )

            .lean();



    const recentActivity =
        recentBeneficiaries.map(

            beneficiary => ({

                type:
                    "beneficiary",

                title:
                    "New beneficiary registered",

                description:
                    `${beneficiary.firstName || ""} ${
                        beneficiary.lastName || ""
                    }`.trim(),

                time:
                    beneficiary.createdAt || null

            })

        );



    // =====================================================
    // FINAL DASHBOARD RESPONSE
    // =====================================================

    return {

        title:
            "Organization Dashboard",


        // =================================================
        // SUMMARY
        // =================================================

        summary: {

            totalBeneficiaries,

            activeBeneficiaries,

            totalPrograms,

            activePrograms,

            completedPrograms,

            plannedPrograms,

            suspendedPrograms,

            cancelledPrograms,

            totalDonors,

            totalFunding,

            totalServices,

            totalServiceValue,

            totalEnrollments,

            activeEnrollments,

            totalProgramBudget,

            totalTargetBeneficiaries

        },


        // =================================================
        // GENDER
        // =================================================

        genderDistribution: {

            male,

            female,

            total:
                genderTotal

        },


        // =================================================
        // PROGRAM PERFORMANCE
        // =================================================

        programPerformance,


        // =================================================
        // STATISTICS
        // =================================================

        statistics: {

            programs: {

                total:
                    totalPrograms,

                active:
                    activePrograms,

                completed:
                    completedPrograms,

                planned:
                    plannedPrograms,

                suspended:
                    suspendedPrograms,

                cancelled:
                    cancelledPrograms

            },


            beneficiaries: {

                total:
                    totalBeneficiaries,

                active:
                    activeBeneficiaries,

                male,

                female

            },


            enrollments: {

                total:
                    totalEnrollments,

                active:
                    activeEnrollments

            },


            budget: {

                total:
                    totalProgramBudget,

                targetBeneficiaries:
                    totalTargetBeneficiaries

            }

        },


        // =================================================
        // CHARTS
        // =================================================

        charts: {

            fundingTrend,

            serviceTrend,

            beneficiariesByProgram

        },


        // =================================================
        // RECENT ACTIVITY
        // =================================================

        recentActivity

    };

};



module.exports = {

    generate

};