const Subscription =
require("../models/Subscription");

const User =
require("../models/User");

const Beneficiary =
require("../models/Beneficiary");

const Donor =
require("../models/Donor");

const Program =
require("../models/Program");

const Donation =
require("../models/Donation");

const ServiceDelivery =
require("../models/ServiceDelivery");



// ==========================================
// Get Active Subscription
// ==========================================

const getOrganizationSubscription = async (
    organizationId
) => {


    const subscription =
        await Subscription.findOne({

            organization:
                organizationId,

            status:"active"

        })
        .populate("plan");



    if(!subscription){

        throw new Error(
            "No active subscription found"
        );

    }


    return subscription;

};




// ==========================================
// Count Usage
// ==========================================

const getUsageCount = async (

    organizationId,

    resource

) => {


    switch(resource){


        case "users":

            return await User.countDocuments({

                organization:
                    organizationId,

                status:"active"

            });



        case "beneficiaries":

            return await Beneficiary.countDocuments({

                organization:
                    organizationId,

                isDeleted:false

            });



        case "donors":

            return await Donor.countDocuments({

                organization:
                    organizationId,

                isDeleted:false

            });



        case "programs":

            return await Program.countDocuments({

                organization:
                    organizationId,

                isDeleted:false

            });



        case "donations":

            return await Donation.countDocuments({

                organization:
                    organizationId,

                isDeleted:false

            });



        case "services":

            return await ServiceDelivery.countDocuments({

                organization:
                    organizationId,

                isDeleted:false

            });



        default:

            throw new Error(
                "Unknown resource"
            );

    }

};





// ==========================================
// Check Limit
// ==========================================

const checkUsageLimit = async (

    organizationId,

    resource

) => {


    const subscription =
        await getOrganizationSubscription(
            organizationId
        );



    const limit =
        subscription.plan.limits[resource];



    // Unlimited plans

    if(
        limit === -1 ||
        limit === undefined
    ){

        return true;

    }




    const currentUsage =
        await getUsageCount(

            organizationId,

            resource

        );




    if(
        currentUsage >= limit
    ){

        throw new Error(

            `You have reached your ${resource} limit. Please upgrade your plan.`

        );

    }



    return true;

};




module.exports = {

    checkUsageLimit,

    getUsageCount,

    getOrganizationSubscription

};