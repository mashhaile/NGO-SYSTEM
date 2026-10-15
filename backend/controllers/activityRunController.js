const activityRunService =
    require("../services/activityRunService");


const subscriptionService =
    require("../services/subscriptionService");



// ======================================================
// CREATE ACTIVITY RUN
// ======================================================

const createActivityRun = async (

    req,

    res

) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==================================================
        // CHECK ACTIVITY RUN LIMIT
        // ==================================================

        await subscriptionService.checkResourceLimit(

            organizationId,

            "activityRuns"

        );


        // ==================================================
        // CREATE ACTIVITY RUN
        // ==================================================

        const activityRun =
            await activityRunService.createActivityRun(

                req.body,

                organizationId,

                req.user.userId

            );


        res.status(201).json({

            success:
                true,

            data:
                activityRun

        });

    }

    catch (error) {

        res.status(400).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// ACTIVITY RUN LOOKUP
// ======================================================

const getActivityRunLookup = async (

    req,

    res

) => {

    try {

        const data =
            await activityRunService
                .getActivityRunLookup(

                    req.user.organizationId

                );


        res.json({

            success:
                true,

            data

        });

    }

    catch (error) {

        res.status(500).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// GET ALL ACTIVITY RUNS
// ======================================================

const getActivityRuns = async (

    req,

    res

) => {

    try {

        const result =
            await activityRunService.getActivityRuns(

                req.user.organizationId,

                req.query

            );


        res.json({

            success:
                true,

            ...result

        });

    }

    catch (error) {

        res.status(500).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// GET SINGLE ACTIVITY RUN
// ======================================================

const getActivityRunById = async (

    req,

    res

) => {

    try {

        const activityRun =
            await activityRunService.getActivityRunById(

                req.params.id,

                req.user.organizationId

            );


        if (!activityRun) {

            return res.status(404).json({

                success:
                    false,

                message:
                    "Activity run not found."

            });

        }


        res.json({

            success:
                true,

            data:
                activityRun

        });

    }

    catch (error) {

        res.status(500).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// UPDATE ACTIVITY RUN
// ======================================================

const updateActivityRun = async (

    req,

    res

) => {

    try {

        const activityRun =
            await activityRunService.updateActivityRun(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        if (!activityRun) {

            return res.status(404).json({

                success:
                    false,

                message:
                    "Activity run not found."

            });

        }


        res.json({

            success:
                true,

            data:
                activityRun

        });

    }

    catch (error) {

        res.status(400).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// DELETE ACTIVITY RUN
// ======================================================

const deleteActivityRun = async (

    req,

    res

) => {

    try {

        const result =
            await activityRunService.deleteActivityRun(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        if (!result) {

            return res.status(404).json({

                success:
                    false,

                message:
                    "Activity run not found."

            });

        }


        res.json({

            success:
                true,

            message:
                "Activity run deleted successfully."

        });

    }

    catch (error) {

        res.status(400).json({

            success:
                false,

            message:
                error.message

        });

    }

};



// ======================================================
// EXPORTS
// ======================================================

module.exports = {

    createActivityRun,

    getActivityRuns,

    getActivityRunById,

    updateActivityRun,

    deleteActivityRun,

    getActivityRunLookup

};