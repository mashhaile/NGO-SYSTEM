const cron =
    require("node-cron");


const runSubscriptionExpiryJob =
    require("./subscriptionExpiryJob");


// =====================================================
// DAILY SUBSCRIPTION LIFECYCLE SCHEDULER
// =====================================================
//
// Runs every day at 08:00 AM Addis Ababa time.
//
// Handles:
// - Trial expiry → Active subscription
// - Trial expiry warnings
// - Subscription expiry
// - Subscription expiry warnings
//
// =====================================================

cron.schedule(

    "0 8 * * *",

    async () => {

        console.log(
            "Running daily subscription lifecycle job..."
        );


        try {

            await runSubscriptionExpiryJob();


            console.log(
                "Daily subscription lifecycle job completed."
            );

        }

        catch (error) {

            console.error(
                "Subscription lifecycle scheduler failed:",
                error
            );

        }

    },

    {

        timezone:
            "Africa/Addis_Ababa"

    }

);


console.log(
    "Background scheduler started. Subscription lifecycle job runs daily at 08:00 AM Addis Ababa time."
);