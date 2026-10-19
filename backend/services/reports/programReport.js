const Program = require("../../models/program");
const Enrollment = require("../../models/enrollment");
const Donation = require("../../models/donation");
const ServiceDelivery = require("../../models/ServiceDelivery");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildCommonFilters,
    buildDateFilter
} = require("./reportFilters");


// =====================================================
// PROGRAM REPORT
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
    // Program selection is mapped directly to Program._id
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
    // BUILD PROGRAM REPORT
    // =====================================================

    for (const program of programs) {


        // =================================================
        // ENROLLMENTS
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
        // UNIQUE BENEFICIARIES
        // =================================================

        const beneficiaryIds =
            new Set();


        for (
            const enrollment
            of enrollments
        ) {

            if (
                enrollment.beneficiary
            ) {

                beneficiaryIds.add(
                    enrollment.beneficiary.toString()
                );

            }

        }


        const beneficiaries =
            beneficiaryIds.size;


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
                "totalAmount"
            );


        // =================================================
        // DONATIONS
        // =================================================

        const donations =
            await Donation.find({

                organization: organizationId,

                program: program._id,

                isDeleted: false,

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
        // TOTAL DONATIONS
        // =================================================

        const totalDonations =
            donations.reduce(
                (
                    sum,
                    donation
                ) => {

                    return (
                        sum +
                        Number(
                            donation.amount || 0
                        )
                    );

                },
                0
            );


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

            beneficiaries,

            donors:
                Array.from(
                    donorNames
                ),

            totalDonations,

            servicesDelivered:
                services.length,

            totalServiceValue

        });

    }


    // =====================================================
    // SUMMARY
    // =====================================================

    const totalBeneficiaries =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.beneficiaries
                );

            },
            0
        );


    const totalDonations =
        report.reduce(
            (
                sum,
                item
            ) => {

                return (
                    sum +
                    item.totalDonations
                );

            },
            0
        );


    const totalServices =
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
            "Program Report",


        summary: {

            totalPrograms:
                report.length,

            totalBeneficiaries,

            totalDonations,

            totalServices,

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
                            item.beneficiaries

                    })
                ),


            donationsByProgram:

                report.map(
                    item => ({

                        program:
                            item.program,

                        programCode:
                            item.programCode,

                        amount:
                            item.totalDonations

                    })
                ),


            servicesByProgram:

                report.map(
                    item => ({

                        program:
                            item.program,

                        programCode:
                            item.programCode,

                        services:
                            item.servicesDelivered

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
