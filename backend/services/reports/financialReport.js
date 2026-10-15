const Donation = require("../../models/Donation");

const {
    buildDateFilter
} = require("./reportFilters");



// Financial Report

const generate = async (
    filters,
    context
) => {

    const {
        organizationId
    } = context;



    const monthly = await Donation.aggregate([

        {
            $match: {

                organization: organizationId,

                isDeleted: false,

                ...buildDateFilter(
                    filters,
                    "donationDate"
                )

            }

        },

        {
            $group: {

                _id: {

                    year: {
                        $year: "$donationDate"
                    },

                    month: {
                        $month: "$donationDate"
                    }

                },

                totalAmount: {
                    $sum: "$amount"
                },

                totalDonations: {
                    $sum: 1
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



    const details = monthly.map(item => ({

        year:
            item._id.year,

        month:
            item._id.month,

        totalAmount:
            item.totalAmount,

        totalDonations:
            item.totalDonations

    }));



    const grandTotal =
        details.reduce(

            (sum, item) =>

                sum + item.totalAmount,

            0

        );



    return {

        title:
            "Financial Report",



        summary: {

            totalMonths:
                details.length,

            totalDonations:

                details.reduce(

                    (sum, item) =>

                        sum + item.totalDonations,

                    0

                ),

            grandTotal

        },



        statistics: {},



        charts: {

            monthlyFunding:

                details.map(item => ({

                    label:
                        `${item.month}/${item.year}`,

                    amount:
                        item.totalAmount

                })),



            monthlyDonations:

                details.map(item => ({

                    label:
                        `${item.month}/${item.year}`,

                    donations:
                        item.totalDonations

                }))

        },



        details

    };

};



module.exports = {

    generate

};