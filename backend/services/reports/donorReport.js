const Donor = require("../../models/donor");
const Donation = require("../../models/donation");
const ServiceDelivery = require("../../models/ServiceDelivery");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildCommonFilters
} = require("./reportFilters");



// Donor Report

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

                isDeleted: false

            })
            .populate(
                "program",
                "name"
            );



        const donationIds =
            donations.map(
                d => d._id
            );



        const servicesDelivered =
            await ServiceDelivery.countDocuments({

                organization: organizationId,

                donation: {
                    $in: donationIds
                },

                isDeleted: false,
                ...COUNTED_DELIVERY_FILTER

            });



        const beneficiaries =
            await ServiceDelivery.distinct(

                "beneficiary",

                {

                    organization: organizationId,

                    donation: {
                        $in: donationIds
                    },

                    isDeleted: false

                }

            );



        report.push({

            donor:
                donor.name,

            donorType:
                donor.donorType,

            programs: [

                ...new Set(

                    donations.map(
                        d => d.program?.name
                    )

                )

            ],

            totalDonations:

                donations.reduce(

                    (sum, donation) =>

                        sum + donation.amount,

                    0

                ),

            servicesDelivered,

            beneficiariesReached:
                beneficiaries.length

        });

    }



    return {

        title:
            "Donor Report",



        summary: {

            totalDonors:
                report.length,

            totalDonations:

                report.reduce(

                    (sum, item) =>

                        sum + item.totalDonations,

                    0

                ),

            totalServices:

                report.reduce(

                    (sum, item) =>

                        sum + item.servicesDelivered,

                    0

                ),

            totalBeneficiariesReached:

                report.reduce(

                    (sum, item) =>

                        sum + item.beneficiariesReached,

                    0

                )

        },



        statistics: {},



        charts: {

            donationsByDonor:

                report.map(item => ({

                    donor:
                        item.donor,

                    amount:
                        item.totalDonations

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