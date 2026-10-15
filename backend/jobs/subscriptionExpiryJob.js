const Subscription =
    require("../models/subscription");


const systemNotificationService =
    require("../services/systemNotificationService");


const {
    SUBSCRIPTION_STATUS,
    BILLING_CYCLES
} =
    require("../config/constants");



// =====================================================
// DATE HELPERS
// =====================================================

const calculateEndDate = (
    billingCycle,
    startDate
) => {

    const date =
        new Date(startDate);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        throw new Error(
            "Invalid subscription start date."
        );

    }


    switch (billingCycle) {

        case BILLING_CYCLES.MONTHLY:

            date.setMonth(
                date.getMonth() + 1
            );

            return date;


        case BILLING_CYCLES.YEARLY:

            date.setFullYear(
                date.getFullYear() + 1
            );

            return date;


        case BILLING_CYCLES.LIFETIME:

            return null;


        default:

            throw new Error(
                "Invalid subscription billing cycle."
            );

    }

};



// =====================================================
// SUBSCRIPTION EXPIRY / TRIAL JOB
// =====================================================

const runSubscriptionExpiryJob = async () => {

    try {

        const today =
            new Date();



        // =================================================
        // 1. CONVERT EXPIRED TRIALS TO ACTIVE SUBSCRIPTIONS
        // =================================================
        //
        // Trial lifecycle:
        //
        // TRIALING
        //      ↓
        // trialEndDate reached
        //      ↓
        // ACTIVE
        //      ↓
        // one billing period
        //
        // The paid subscription starts exactly when
        // the trial ends.
        //
        // =================================================

        const expiredTrials =
            await Subscription.find({

                status:
                    SUBSCRIPTION_STATUS.TRIALING,

                trialEndDate: {

                    $lte:
                        today

                }

            });



        for (
            const subscription
            of expiredTrials
        ) {

            try {

                if (
                    !subscription.planSnapshot
                ) {

                    console.error(
                        `Trial ${subscription._id} has no plan snapshot.`
                    );

                    continue;

                }


                const billingCycle =
                    subscription
                        .planSnapshot
                        .billingCycle;


                if (
                    !billingCycle
                ) {

                    console.error(
                        `Trial ${subscription._id} has no billing cycle.`
                    );

                    continue;

                }


                // -----------------------------------------
                // Lifetime plans do not need paid renewal
                // -----------------------------------------

                const paidStartDate =
                    new Date(
                        subscription.trialEndDate
                    );


                const paidEndDate =
                    calculateEndDate(

                        billingCycle,

                        paidStartDate

                    );


                // -----------------------------------------
                // Convert trial to active subscription
                // -----------------------------------------

                subscription.startDate =
                    paidStartDate;


                subscription.endDate =
                    paidEndDate;


                subscription.status =
                    SUBSCRIPTION_STATUS.ACTIVE;


                subscription.autoRenew =
                    false;


                subscription.cancelAtPeriodEnd =
                    false;


                subscription.cancelledAt =
                    null;


                subscription.cancellationReason =
                    "";


                await subscription.save();



                // -----------------------------------------
                // Notify organization
                // -----------------------------------------

                await systemNotificationService
                    .notifyOrganizationAdmins(

                        subscription.organization,

                        "Trial Ended",

                        "Your free trial has ended and your paid subscription is now active.",

                        "subscription"

                    );



                console.log(
                    `Trial converted to active subscription: ${subscription._id}`
                );

            }

            catch (error) {

                console.error(

                    `Failed to convert trial ${subscription._id}:`,

                    error.message

                );

            }

        }



        // =================================================
        // 2. TRIALS EXPIRING WITHIN 7 DAYS
        // =================================================

        const sevenDaysFromNow =
            new Date(

                today.getTime()
                +
                7 *
                24 *
                60 *
                60 *
                1000

            );



        const trialsExpiringSoon =
            await Subscription.find({

                status:
                    SUBSCRIPTION_STATUS.TRIALING,

                trialEndDate: {

                    $gt:
                        today,

                    $lte:
                        sevenDaysFromNow

                }

            });



        for (
            const subscription
            of trialsExpiringSoon
        ) {

            try {

                if (
                    !subscription.trialEndDate
                ) {

                    continue;

                }


                await systemNotificationService
                    .notifyOrganizationAdmins(

                        subscription.organization,

                        "Trial Expiring Soon",

                        `Your free trial will end on ${subscription.trialEndDate.toDateString()}. Your paid subscription will begin automatically after the trial ends.`,

                        "subscription"

                    );


                console.log(
                    `Trial expiry warning sent: ${subscription._id}`
                );

            }

            catch (error) {

                console.error(

                    `Failed to send trial warning for ${subscription._id}:`,

                    error.message

                );

            }

        }



        // =================================================
        // 3. EXPIRE ACTIVE SUBSCRIPTIONS
        // =================================================

        const expiredSubscriptions =
            await Subscription.find({

                status:
                    SUBSCRIPTION_STATUS.ACTIVE,

                endDate: {

                    $ne:
                        null,

                    $lte:
                        today

                }

            });



        for (
            const subscription
            of expiredSubscriptions
        ) {

            try {

                subscription.status =
                    SUBSCRIPTION_STATUS.EXPIRED;


                subscription.cancelAtPeriodEnd =
                    false;


                await subscription.save();



                await systemNotificationService
                    .notifyOrganizationAdmins(

                        subscription.organization,

                        "Subscription Expired",

                        "Your subscription has expired. Please renew your plan to continue using subscription-protected features.",

                        "subscription"

                    );



                console.log(
                    `Expired subscription: ${subscription._id}`
                );

            }

            catch (error) {

                console.error(

                    `Failed to expire subscription ${subscription._id}:`,

                    error.message

                );

            }

        }



        // =================================================
        // 4. PAID SUBSCRIPTIONS EXPIRING WITHIN 7 DAYS
        // =================================================

        const expiringSubscriptions =
            await Subscription.find({

                status:
                    SUBSCRIPTION_STATUS.ACTIVE,

                endDate: {

                    $gt:
                        today,

                    $lte:
                        sevenDaysFromNow

                }

            });



        for (
            const subscription
            of expiringSubscriptions
        ) {

            try {

                if (
                    !subscription.endDate
                ) {

                    continue;

                }


                await systemNotificationService
                    .notifyOrganizationAdmins(

                        subscription.organization,

                        "Subscription Expiring Soon",

                        `Your subscription will expire on ${subscription.endDate.toDateString()}. Please renew before expiration to avoid interruption.`,

                        "subscription"

                    );


                console.log(
                    `Subscription expiry warning sent: ${subscription._id}`
                );

            }

            catch (error) {

                console.error(

                    `Failed to send expiry warning for ${subscription._id}:`,

                    error.message

                );

            }

        }



        // =================================================
        // COMPLETED
        // =================================================

        console.log(
            "Subscription lifecycle job completed successfully."
        );

    }

    catch (error) {

        console.error(
            "Subscription lifecycle job failed:",
            error.message
        );

    }

};



module.exports =
    runSubscriptionExpiryJob;