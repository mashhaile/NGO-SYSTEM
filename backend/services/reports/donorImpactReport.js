const Donor = require("../../models/Donor");
const Donation = require("../../models/Donation");
const ServiceDelivery = require("../../models/ServiceDelivery");

const {
    buildCommonFilters,
    buildDateFilter
} = require("./reportFilters");



// Donor Impact Report

const generate = async (
    filters,
    context
) => {

    const {
        organizationId
    } = context;



    const donorQuery = {

        organization: organizationId,

        isDeleted: false,

        ...buildCommonFilters(
            filters,
            context
        )

    };



    const donors =
        await Donor.find(
            donorQuery
        );



    const report = [];



    for (const donor of donors) {

        const donations =
            await Donation.find({

                organization: organizationId,

                donor: donor._id,

                isDeleted: false,

                ...buildDateFilter(
                    filters,
                    "donationDate"
                )

            });



        const donationIds =
            donations.map(
                d => d._id
            );



        const services =
            await ServiceDelivery.find({

                organization: organizationId,

                donation: {
                    $in: donationIds
                },

                isDeleted: false,

                ...buildDateFilter(
                    filters,
                    "serviceDate"
                )

            });



        const beneficiaries = [

            ...new Set(

                services.map(
                    s => s.beneficiary.toString()
                )

            )

        ];



        const programs = [

            ...new Set(

                donations.map(
                    d => d.program.toString()
                )

            )

        ];



        const totalDonated =
            donations.reduce(

                (sum, donation) =>

                    sum + donation.amount,

                0

            );



        const totalServiceValue =
            services.reduce(

                (sum, service) =>

                    sum + service.amount,

                0

            );



        report.push({

            donor:
                donor.name,

            donorType:
                donor.donorType,

            totalDonated,

            programsSupported:
                programs.length,

            beneficiariesReached:
                beneficiaries.length,

            servicesDelivered:
                services.length,

            totalServiceValue,

            impact: {

                averageSupportPerBeneficiary:

                    beneficiaries.length > 0

                        ? Math.round(
                            totalServiceValue /
                            beneficiaries.length
                        )

                        : 0

            }

        });

    }



    return {

        title:
            "Donor Impact Report",



        summary: {

            totalDonors:
                report.length,

            totalFunding:

                report.reduce(

                    (sum, item) =>

                        sum + item.totalDonated,

                    0

                ),

            totalBeneficiariesReached:

                report.reduce(

                    (sum, item) =>

                        sum + item.beneficiariesReached,

                    0

                ),

            totalServicesDelivered:

                report.reduce(

                    (sum, item) =>

                        sum + item.servicesDelivered,

                    0

                )

        },



        statistics: {},



        charts: {

            fundingByDonor:

                report.map(item => ({

                    donor:
                        item.donor,

                    amount:
                        item.totalDonated

                })),



            beneficiariesByDonor:

                report.map(item => ({

                    donor:
                        item.donor,

                    beneficiaries:
                        item.beneficiariesReached

                })),



            servicesByDonor:

                report.map(item => ({

                    donor:
                        item.donor,

                    services:
                        item.servicesDelivered

                }))

        },



        details:
            report

    };

};



module.exports = {

    generate

};