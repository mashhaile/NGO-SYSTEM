const Organization = require("../models/organization");
const User = require("../models/user");
const Subscription = require("../models/subscription");
const Plan = require("../models/plan");
const Beneficiary = require("../models/Beneficiary");
const Donor = require("../models/donor");
const Program = require("../models/program");


const getAdminDashboard = async () => {

    const [

        totalOrganizations,

        activeOrganizations,

        totalUsers,

        totalBeneficiaries,

        totalDonors,

        totalPrograms,

        activeSubscriptions,

        plans

    ] = await Promise.all([


        Organization.countDocuments(),


        Organization.countDocuments({
            status:"Active"
        }),


        User.countDocuments({
            isDeleted:false
        }),


        Beneficiary.countDocuments({
            isDeleted:false
        }),


        Donor.countDocuments({
            isDeleted:false
        }),


        Program.countDocuments({
            isDeleted:false
        }),


        Subscription.countDocuments({
            status:"active"
        }),


        Plan.find({
            isActive:true
        })

    ]);



    const subscriptionsByPlan =
        await Subscription.aggregate([

            {
                $match:{
                    status:"active"
                }
            },


            {
                $lookup:{

                    from:"plans",

                    localField:"plan",

                    foreignField:"_id",

                    as:"plan"

                }

            },


            {
                $unwind:"$plan"
            },


            {
                $group:{

                    _id:"$plan.name",

                    count:{
                        $sum:1
                    }

                }

            }

        ]);




    return {


        organizations:{

            total:
            totalOrganizations,

            active:
            activeOrganizations

        },


        users:
            totalUsers,


        beneficiaries:
            totalBeneficiaries,


        donors:
            totalDonors,


        programs:
            totalPrograms,


        subscriptions:{

            active:
            activeSubscriptions,

            byPlan:
            subscriptionsByPlan

        },


        availablePlans:
            plans.length

    };


};



module.exports = {

    getAdminDashboard

};