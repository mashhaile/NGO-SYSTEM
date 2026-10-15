const activityService =
    require("../services/activityService");


const subscriptionService =
    require("../services/subscriptionService");



// ==========================================
// CREATE ACTIVITY
// ==========================================

const createActivity = async (

    req,
    res,
    next

) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==========================================
        // CHECK ACTIVITY LIMIT
        // ==========================================

        await subscriptionService.checkResourceLimit(

            organizationId,

            "activities"

        );


        // ==========================================
        // CREATE ACTIVITY
        // ==========================================

        const activity =

            await activityService.createActivity(

                req.body,

                organizationId,

                req.user.userId

            );


        res.status(201).json({

            success: true,

            message:
                "Activity created successfully",

            data:
                activity

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// GET ACTIVITIES
// ==========================================

const getActivities = async (

    req,
    res,
    next

) => {

    try {

        const result =

            await activityService.getActivities(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            ...result

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// GET SINGLE ACTIVITY
// ==========================================

const getActivityById = async (

    req,
    res,
    next

) => {

    try {

        const activity =

            await activityService.getActivityById(

                req.params.id,

                req.user.organizationId

            );


        if (!activity) {

            return res.status(404).json({

                success: false,

                message:
                    "Activity not found"

            });

        }


        res.json({

            success: true,

            data:
                activity

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// UPDATE ACTIVITY
// ==========================================

const updateActivity = async (

    req,
    res,
    next

) => {

    try {

        const activity =

            await activityService.updateActivity(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        if (!activity) {

            return res.status(404).json({

                success: false,

                message:
                    "Activity not found"

            });

        }


        res.json({

            success: true,

            message:
                "Activity updated successfully",

            data:
                activity

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// DELETE ACTIVITY
// ==========================================

const deleteActivity = async (

    req,
    res,
    next

) => {

    try {

        const activity =

            await activityService.deleteActivity(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        if (!activity) {

            return res.status(404).json({

                success: false,

                message:
                    "Activity not found"

            });

        }


        res.json({

            success: true,

            message:
                "Activity deleted successfully"

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// ACTIVITY LOOKUP
// Used for Activity Run dropdown
// ==========================================

const getActivityLookup = async (

    req,
    res,
    next

) => {

    try {

        const activities =

            await activityService.getActivityLookup(

                req.user.organizationId

            );


        res.json({

            success: true,

            data:
                activities

        });

    }

    catch (error) {

        next(error);

    }

};



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createActivity,

    getActivities,

    getActivityById,

    updateActivity,

    deleteActivity,

    getActivityLookup

};