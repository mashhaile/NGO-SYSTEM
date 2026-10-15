const Subscription =
require("../models/subscription");

const systemNotificationService =
require("./systemNotificationService");



// ==========================================
// Notify Expiring Subscriptions
// ==========================================

const notifyExpiringSubscriptions = async () => {


    const today = new Date();


    const futureDate = new Date();

    futureDate.setDate(
        today.getDate() + 7
    );



    const subscriptions =
        await Subscription.find({

            status:"active",

            endDate:{
                $lte:futureDate,
                $gte:today
            }

        });



    for(
        const subscription of subscriptions
    ){


        await systemNotificationService
        .notifyOrganizationAdmins(

            subscription.organization,

            "Subscription Expiring Soon",

            "Your subscription will expire within 7 days. Please renew your plan.",

            "subscription"

        );


    }


};



module.exports = {

    notifyExpiringSubscriptions

};