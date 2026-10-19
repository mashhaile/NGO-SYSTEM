const ServiceDelivery = require("../../models/ServiceDelivery");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildDateFilter
} = require("./reportFilters");



// Monthly Service Report

const generate = async (

    filters,

    context

) => {


    const {
        organizationId
    } = context;



    const monthly =
        await ServiceDelivery.aggregate([


            {
                $match: {

                    organization:
                        organizationId,

                    isDeleted:
                        false,
                    ...COUNTED_DELIVERY_FILTER,


                    ...buildDateFilter(

                        filters,

                        "serviceDate"

                    )

                }

            },



            {
                $group: {


                    _id: {


                        year: {

                            $year:
                                "$serviceDate"

                        },


                        month: {

                            $month:
                                "$serviceDate"

                        }


                    },


                    services: {

                        $sum: 1

                    },


                    beneficiaries: {

                        $addToSet:
                            "$beneficiary"

                    },


                    totalValue: {

                        $sum:
                            "$amount"

                    }


                }

            },



            {
                $project: {


                    _id:0,


                    year:
                        "$_id.year",


                    month:
                        "$_id.month",


                    services:1,


                    beneficiaries: {

                        $size:
                            "$beneficiaries"

                    },


                    totalValue:1


                }

            },



            {
                $sort: {

                    year:1,

                    month:1

                }

            }


        ]);





    return {


        title:
            "Monthly Service Report",



        summary: {


            totalMonths:
                monthly.length,


            totalServices:

                monthly.reduce(

                    (sum,item)=>

                        sum + item.services,

                    0

                ),


            totalBeneficiaries:

                monthly.reduce(

                    (sum,item)=>

                        sum + item.beneficiaries,

                    0

                ),



            totalValue:

                monthly.reduce(

                    (sum,item)=>

                        sum + item.totalValue,

                    0

                )


        },



        statistics:{},



        charts:{


            servicesByMonth:


                monthly.map(item=>({


                    month:
                        `${item.month}/${item.year}`,


                    services:
                        item.services


                })),



            valueByMonth:


                monthly.map(item=>({


                    month:
                        `${item.month}/${item.year}`,


                    amount:
                        item.totalValue


                }))


        },



        details:
            monthly


    };


};





module.exports = {

    generate

};