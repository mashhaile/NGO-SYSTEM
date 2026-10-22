const Program = require("../../models/program");
const Enrollment = require("../../models/enrollment");
const Donation = require("../../models/donation");

const {
    formatTotals
} = require("../budgetFigures");
const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildCommonFilters,
    buildDateFilter
} = require("./reportFilters");


// =====================================================
// PROGRAM IMPACT REPORT
// =====================================================

const generate = async (
    filters = {},
    context
) => {

    const {
        organizationId
    } = context;


    // =====================================================
    // PROGRAM QUERY
    // =====================================================

    const programQuery = {

        organization: organizationId,

        isDeleted: false,

        ...buildCommonFilters(
            filters,
            context
        )

    };


    // =====================================================
    // PROGRAM FILTER
    // =====================================================

    if (filters.program) {

        programQuery._id =
            filters.program;

    }


    // =====================================================
    // LOAD PROGRAMS
    // =====================================================

    const programs =
        await Program.find(
            programQuery
        )
        .sort({
            name: 1
        });


    const report = [];


    // =====================================================
    // BUILD IMPACT REPORT
    // =====================================================

    // Received funding: all programs per currency; ETB per program (charts)
    const allFunding = {};
    const etbByProgram = new Map();

    for (const program of programs) {


        // =================================================
        // PROGRAM ENROLLMENTS
        // =================================================

        const enrollments =
            await Enrollment.find({

                organization: organizationId,

                program: program._id,

                isDeleted: false,

                ...buildDateFilter(
                    filters,
                    "enrollmentDate"
                )

            })
            .select(
                "beneficiary"
            );


        // =================================================
        // UNIQUE ENROLLED BENEFICIARIES
        // =================================================

        const enrolledBeneficiaryIds =
            new Set();


        for (
            const enrollment
            of enrollments
        ) {

            if (
                enrollment.beneficiary
            ) {

                enrolledBeneficiaryIds.add(
                    enrollment.beneficiary.toString()
                );

            }

        }


        // =================================================
        // DONATIONS / FUNDING
        // =================================================

        const donations =
            await Donation.find({

                organization: organizationId,

                program: program._id,

                isDeleted: false,

                // Received only: a pledge is not funding yet
                status: "Received",

                ...buildDateFilter(
                    filters,
                    "donationDate"
                )

            })
            .populate(
                "donor",
                "name"
            );


        // =================================================
        // SERVICE DELIVERIES
        // =================================================

        const services =
            await ServiceDelivery.find({

                organization: organizationId,

                program: program._id,

                isDeleted: false,
                ...COUNTED_DELIVERY_FILTER,

                ...buildDateFilter(
                    filters,
                    "deliveryDate"
                )

            })
            .select(
                "_id totalAmount"
            );


        // =================================================
        // SERVICE DELIVERY IDS
        // =================================================

        const serviceDeliveryIds =
            services.map(
                service =>
                    service._id
            );


        // =================================================
        // SERVICE DELIVERY BENEFICIARIES
        // =================================================

        let serviceBeneficiaries = [];


        if (
            serviceDeliveryIds.length > 0
        ) {

            serviceBeneficiaries =
                await ServiceDeliveryBeneficiary.find({

                    organization: organizationId,

                    serviceDelivery: {
                        $in: serviceDeliveryIds
                    },

                    status: {
                        $in: [
                            "Received",
                            "Participated"
                        ]
                    }

                })
                .select(
                    "beneficiary serviceDelivery status"
                );

        }


        // =================================================
        // UNIQUE BENEFICIARIES ACTUALLY REACHED
        // =================================================

        const reachedBeneficiaryIds =
            new Set();


        for (
            const serviceBeneficiary
            of serviceBeneficiaries
        ) {

            if (
                serviceBeneficiary.beneficiary
            ) {

                reachedBeneficiaryIds.add(
                    serviceBeneficiary.beneficiary.toString()
                );

            }

        }


        // =================================================
        // TOTAL FUNDING
        // =================================================

        // Per currency (ETB and EUR are never added together)
        const fundingByCurrency = {};

        for (const donation of donations) {
            const currency = donation.currency || "ETB";
            fundingByCurrency[currency] =
                (fundingByCurrency[currency] || 0) + Number(donation.amount || 0);
            allFunding[currency] =
                (allFunding[currency] || 0) + Number(donation.amount || 0);
        }

        etbByProgram.set(String(program._id), fundingByCurrency.ETB || 0);

        const totalFunding =
            formatTotals(fundingByCurrency);


        // =================================================
        // TOTAL SERVICE VALUE
        // =================================================

        const totalServiceValue =
            services.reduce(
                (
                    sum,
                    service
                ) => {

                    return (
                        sum +
                        Number(
                            service.totalAmount || 0
                        )
                    );

                },
                0
            );


        // =================================================
        // UNIQUE DONORS
        // =================================================

        const donorNames =
            new Set();


        for (
            const donation
            of donations
        ) {

            if (
                donation.donor &&
                donation.donor.name
            ) {

                donorNames.add(
                    donation.donor.name
                );

            }

        }


        // =================================================
        // BENEFICIARIES REACHED
        // =================================================

        const beneficiariesReached =
            reachedBeneficiaryIds.size;


        // =================================================
        // AVERAGE SUPPORT
        // =================================================

        const averageSupportPerBeneficiary =
            beneficiariesReached > 0
                ? Math.round(
                    totalServiceValue /
                    beneficiariesReached
                )
                : 0;


        // =================================================
        // REPORT ROW
        // =================================================

        report.push({

            programId:
                program._id,

            programCode:
                program.programCode,

            program:
                program.name,

            status:
                program.status,

            beneficiariesEnrolled:
                enrolledBeneficiaryIds.size,

            beneficiariesReached,

            donors:
                Array.from(
                    donorNames
                ),

            totalFunding,

            servicesDelivered:
                services.length,

            totalServiceValue,

            impact: {

                averageSupportPerBeneficiary

            }

        });

    }


    // =====================================================
    // SUMMARY
    // =====================================================

    const totalFunding =
        formatTotals(allFunding);


    const totalServicesDelivered =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.servicesDelivered
                );

            },
            0
        );


    const totalBeneficiariesReached =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.beneficiariesReached
                );

            },
            0
        );


    const totalBeneficiariesEnrolled =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.beneficiariesEnrolled
                );

            },
            0
        );


    const totalServiceValue =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.totalServiceValue
                );

            },
            0
        );


    // =====================================================
    // RETURN REPORT
    // =====================================================

    return {

        title:
            "Program Impact Report",


        summary: {

            totalPrograms:
                report.length,

            totalBeneficiariesEnrolled,

            totalBeneficiariesReached,

            totalFunding,

            totalServicesDelivered,

            totalServiceValue

        },


        statistics: {},


        charts: {

            beneficiariesByProgram:

                report.map(
                    item => ({

                        program:
                            item.program,

                        programCode:
                            item.programCode,

                        beneficiaries:
                            item.beneficiariesReached

                    })
                ),


            fundingByProgram:

                report.map(
                    item => ({

                        program:
                            item.program,

                        programCode:
                            item.programCode,

                        amount:
                            etbByProgram.get(String(item.programId)) || 0

                    })
                ),


            serviceValueByProgram:

                report.map(
                    item => ({

                        program:
                            item.program,

                        programCode:
                            item.programCode,

                        amount:
                            item.totalServiceValue

                    })
                )

        },


        details:
            report

    };

};


module.exports = {

    generate

};
