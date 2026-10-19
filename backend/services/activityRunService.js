const ActivityRun =
    require("../models/ActivityRun");

const Activity =
    require("../models/Activity");



// =====================================================
// CREATE ACTIVITY RUN
// =====================================================

const createActivityRun = async (

    data,

    organizationId,

    userId

) => {

    // =================================================
    // LOAD ACTIVITY
    // =================================================

    const activity =
        await Activity.findOne({

            _id:
                data.activity,

            organization:
                organizationId,

            isDeleted:
                false

        })

        .populate({

            path:
                "project",

            populate: {

                path:
                    "program"

            }

        });


    if (!activity) {

        throw new Error(
            "Activity not found."
        );

    }


    // =================================================
    // VALIDATE PROJECT
    // =================================================

    if (!activity.project) {

        throw new Error(
            "Activity project not found."
        );

    }


    // =================================================
    // VALIDATE PROGRAM
    // =================================================

    if (!activity.project.program) {

        throw new Error(
            "Activity program not found."
        );

    }


    // =================================================
    // GENERATE RUN CODE
    // =================================================

    const totalRuns =
        await ActivityRun.countDocuments({

            organization:
                organizationId,

            activity:
                data.activity

        });


    const runCode =

        `${activity.activityCode}-RUN-${String(
            totalRuns + 1
        ).padStart(3, "0")}`;


    // =================================================
    // CREATE
    // =================================================

    const activityRun =
        await ActivityRun.create({

            organization:
                organizationId,

            activity:
                activity._id,

            // Derived from Activity
            project:
                activity.project._id,

            // Derived from Project
            program:
                activity.project.program._id,

            runCode,

            name:
                data.name,

            startDate:
                data.startDate,

            endDate:
                data.endDate || null,

            region:
                data.region || null,

            regionCode:
                data.regionCode || null,

            zone:
                data.zone || null,

            zoneCode:
                data.zoneCode || null,

            woreda:
                data.woreda || null,

            woredaCode:
                data.woredaCode || null,

            location:
                data.location || null,

            trainer:
                data.trainer || null,

            targetGroup:
                data.targetGroup || null,

            status:
                data.status || "Planned",

            notes:
                data.notes || null,

            createdBy:
                userId

        });


    // =================================================
    // RETURN POPULATED RESULT
    // =================================================

    return ActivityRun.findById(

        activityRun._id

    )

        .populate(
            "activity",
            "activityCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        )

        .populate(
            "trainer",
            "name email"
        );

};



// =====================================================
// ACTIVITY RUN LOOKUP
//
// Used by:
// - Donation
// - Attendance
// - Other modules
// =====================================================

const getActivityRunLookup = async (

    organizationId

) => {

    return ActivityRun.find({

        organization:
            organizationId,

        isDeleted:
            false

    })

        .select(
            "_id runCode name activity"
        )

        .sort({

            createdAt:
                -1

        });

};



// =====================================================
// GET ALL ACTIVITY RUNS
// =====================================================

const getActivityRuns = async (

    organizationId,

    query = {}

) => {

    const {

        search = "",

        activity,

        project,

        status,

        page = 1,

        limit = 10

    } = query;


    // =================================================
    // BASE FILTER
    // =================================================

    const filter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // ACTIVITY FILTER
    // =================================================

    if (activity) {

        filter.activity =
            activity;

    }


    // =================================================
    // PROJECT FILTER
    // =================================================

    if (project) {

        filter.project =
            project;

    }


    // =================================================
    // STATUS FILTER
    // =================================================

    if (status) {

        filter.status =
            status;

    }


    // =================================================
    // SEARCH
    // =================================================

    if (search) {

        filter.$or = [

            {

                name: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            },

            {

                runCode: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            }

        ];

    }


    // =================================================
    // PAGINATION
    // =================================================

    const pageNumber =
        Number(page);

    const limitNumber =
        Number(limit);

    const skip =
        (pageNumber - 1) *
        limitNumber;


    // =================================================
    // QUERY
    // =================================================

    const [

        data,

        total

    ] = await Promise.all([

        ActivityRun.find(filter)

            .populate(
                "activity",
                "activityCode name"
            )

            .populate(
                "project",
                "projectCode name"
            )

            .populate(
                "program",
                "programCode name"
            )

            .populate(
                "trainer",
                "name email"
            )

            .sort({

                createdAt:
                    -1

            })

            .skip(skip)

            .limit(limitNumber),


        ActivityRun.countDocuments(
            filter
        )

    ]);


    // =================================================
    // RESULT
    // =================================================

    return {

        data,

        pagination: {

            total,

            page:
                pageNumber,

            limit:
                limitNumber,

            pages:
                Math.ceil(
                    total /
                    limitNumber
                )

        }

    };

};



// =====================================================
// GET SINGLE ACTIVITY RUN
// =====================================================

const getActivityRunById = async (

    id,

    organizationId

) => {

    return ActivityRun.findOne({

        _id:
            id,

        organization:
            organizationId,

        isDeleted:
            false

    })

        .populate(
            "activity",
            "activityCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        )

        .populate(
            "trainer",
            "name email"
        );

};



// =====================================================
// UPDATE ACTIVITY RUN
//
// IMPORTANT:
// Activity, project, program and runCode
// cannot be changed.
// =====================================================

const updateActivityRun = async (

    id,

    data,

    organizationId,

    userId

) => {

    // =================================================
    // FIND EXISTING RUN
    // =================================================

    const activityRun =
        await ActivityRun.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!activityRun) {

        return null;

    }


    // =================================================
    // UPDATE ONLY SUPPLIED FIELDS
    // =================================================

    if (
        data.name !==
        undefined
    ) {

        activityRun.name =
            data.name;

    }


    if (
        data.startDate !==
        undefined
    ) {

        activityRun.startDate =
            data.startDate;

    }


    if (
        data.endDate !==
        undefined
    ) {

        activityRun.endDate =
            data.endDate;

    }


    if (
        data.location !==
        undefined
    ) {

        activityRun.location =
            data.location;

    }


    [
        "region",
        "regionCode",
        "zone",
        "zoneCode",
        "woreda",
        "woredaCode"
    ].forEach(field => {

        if (data[field] !== undefined) {

            activityRun[field] =
                data[field] || null;

        }

    });


    if (
        data.trainer !==
        undefined
    ) {

        activityRun.trainer =
            data.trainer;

    }


    if (
        data.targetGroup !==
        undefined
    ) {

        activityRun.targetGroup =
            data.targetGroup;

    }


    if (
        data.status !==
        undefined
    ) {

        activityRun.status =
            data.status;

    }


    if (
        data.notes !==
        undefined
    ) {

        activityRun.notes =
            data.notes;

    }


    // =================================================
    // AUDIT
    // =================================================

    activityRun.updatedBy =
        userId;


    // =================================================
    // SAVE
    // =================================================

    await activityRun.save();


    // =================================================
    // RETURN POPULATED RESULT
    // =================================================

    return ActivityRun.findById(

        activityRun._id

    )

        .populate(
            "activity",
            "activityCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        )

        .populate(
            "trainer",
            "name email"
        );

};



// =====================================================
// DELETE ACTIVITY RUN
// =====================================================

const deleteActivityRun = async (

    id,

    organizationId,

    userId

) => {

    return ActivityRun.findOneAndUpdate(

        {

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        },

        {

            isDeleted:
                true,

            deletedAt:
                new Date(),

            deletedBy:
                userId

        },

        {

            new:
                true

        }

    );

};



// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createActivityRun,

    getActivityRunLookup,

    getActivityRuns,

    getActivityRunById,

    updateActivityRun,

    deleteActivityRun

};