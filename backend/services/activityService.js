const Activity = require("../models/Activity");
const Project = require("../models/Project");
const ActivityRun = require("../models/ActivityRun");


// ==========================================
// GENERATE ACTIVITY CODE
// ==========================================

const generateActivityCode = async (

    organizationId,

    projectId,

    projectCode

) => {

    let number =

        await Activity.countDocuments({

            organization:
                organizationId,

            project:
                projectId

        }) + 1;


    while (true) {

        const activityCode =

            `${projectCode}-ACT-${String(number).padStart(3, "0")}`;


        const exists =

            await Activity.findOne({

                organization:
                    organizationId,

                activityCode

            });


        if (!exists) {

            return activityCode;

        }


        number++;

    }

};



// ==========================================
// VALIDATE PROJECT
// ==========================================

const validateProject = async (

    projectId,

    organizationId

) => {

    if (!projectId) {

        throw new Error(
            "Project is required."
        );

    }


    const project =

        await Project.findOne({

            _id:
                projectId,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!project) {

        throw new Error(
            "Project not found."
        );

    }


    return project;

};



// ==========================================
// CREATE ACTIVITY
// ==========================================

const createActivity = async (

    data,

    organizationId,

    userId

) => {

    const project =

        await validateProject(

            data.project,

            organizationId

        );


    const activityCode =

        await generateActivityCode(

            organizationId,

            project._id,

            project.projectCode

        );


    const activity =

        await Activity.create({

            organization:
                organizationId,

            project:
                project._id,

            activityCode,


            name:
                data.name,

            activityType:
                data.activityType,

            participantSource:
                data.participantSource,

            targetGroups:
                data.targetGroups || [],

            description:
                data.description,

            activityDate:
                data.activityDate,

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
                data.location,

            facilitator:
                data.facilitator,

            targetParticipants:
                data.targetParticipants || 0,

            status:
                data.status,

            remarks:
                data.remarks,


            createdBy:
                userId

        });


    return Activity.findById(

        activity._id

    )

        .populate(

            "project",

            "projectCode name"

        );

};



// ==========================================
// GET ACTIVITIES
// ==========================================

const getActivities = async (

    organizationId,

    query = {}

) => {

    const {

        search = "",

        page = 1,

        limit = 10,

        project,

        activityType,

        participantSource,

        status

    } = query;


    const filter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    if (project) {

        filter.project =
            project;

    }


    if (activityType) {

        filter.activityType =
            activityType;

    }


    if (participantSource) {

        filter.participantSource =
            participantSource;

    }


    if (status) {

        filter.status =
            status;

    }


    if (search) {

        filter.$or = [

            {

                activityCode: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            },

            {

                name: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            },

            {

                facilitator: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            },

            {

                location: {

                    $regex:
                        search,

                    $options:
                        "i"

                }

            }

        ];

    }


    const skip =

        (Number(page) - 1) *
        Number(limit);


    const [

        activities,

        total

    ] = await Promise.all([

        Activity.find(filter)

            .populate(

                "project",

                "projectCode name"

            )

            .sort({

                activityDate:
                    -1

            })

            .skip(skip)

            .limit(Number(limit)),


        Activity.countDocuments(
            filter
        )

    ]);


    return {

        data:
            activities,

        pagination: {

            total,

            page:
                Number(page),

            limit:
                Number(limit),

            pages:
                Math.ceil(

                    total /
                    Number(limit)

                )

        }

    };

};



// ==========================================
// GET SINGLE ACTIVITY
// ==========================================

const getActivityById = async (

    id,

    organizationId

) => {

    return Activity.findOne({

        _id:
            id,

        organization:
            organizationId,

        isDeleted:
            false

    })

        .populate(

            "project",

            "projectCode name"

        );

};



// ==========================================
// UPDATE ACTIVITY
// ==========================================

const updateActivity = async (

    id,

    data,

    organizationId,

    userId

) => {

    const activity =

        await Activity.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!activity) {

        return null;

    }


    // ==========================================
    // HANDLE PROJECT CHANGE
    // ==========================================

    let projectChanged = false;
    let newProject = null;


    if (
        data.project !== undefined &&
        data.project !== null &&
        data.project !== ""
    ) {

        newProject =

            await validateProject(

                data.project,

                organizationId

            );


        projectChanged =

            String(activity.project) !==
            String(newProject._id);

    }


    // ==========================================
    // UPDATE ACTIVITY
    // ==========================================

    if (data.project !== undefined) {

        activity.project =
            newProject._id;

    }


    if (data.name !== undefined) {

        activity.name =
            data.name;

    }


    if (data.activityType !== undefined) {

        activity.activityType =
            data.activityType;

    }


    if (data.participantSource !== undefined) {

        activity.participantSource =
            data.participantSource;

    }


    if (data.targetGroups !== undefined) {

        activity.targetGroups =
            data.targetGroups;

    }


    if (data.description !== undefined) {

        activity.description =
            data.description;

    }


    if (data.activityDate !== undefined) {

        activity.activityDate =
            data.activityDate;

    }


    if (data.location !== undefined) {

        activity.location =
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

            activity[field] =
                data[field] || null;

        }

    });


    if (data.facilitator !== undefined) {

        activity.facilitator =
            data.facilitator;

    }


    if (data.targetParticipants !== undefined) {

        activity.targetParticipants =
            data.targetParticipants;

    }


    if (data.status !== undefined) {

        activity.status =
            data.status;

    }


    if (data.remarks !== undefined) {

        activity.remarks =
            data.remarks;

    }


    activity.updatedBy =
        userId;


    await activity.save();


    // ==========================================
    // SYNC ACTIVITY RUNS
    // ==========================================

    if (projectChanged) {

        await ActivityRun.updateMany(

            {

                organization:
                    organizationId,

                activity:
                    activity._id,

                isDeleted:
                    false

            },

            {

                $set: {

                    project:
                        newProject._id,

                    program:
                        newProject.program,

                    updatedBy:
                        userId

                }

            }

        );

    }


    // ==========================================
    // RETURN UPDATED ACTIVITY
    // ==========================================

    return Activity.findById(

        activity._id

    )

        .populate(

            "project",

            "projectCode name"

        );

};



// ==========================================
// DELETE ACTIVITY
// ==========================================

const deleteActivity = async (

    id,

    organizationId,

    userId

) => {

    return Activity.findOneAndUpdate(

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



// ==========================================
// ACTIVITY LOOKUP
// ==========================================

const getActivityLookup = async (

    organizationId

) => {

    return Activity.find({

        organization:
            organizationId,

        isDeleted:
            false

    })

        .select(
            "_id activityCode name project"
        )

        .sort({

            name:
                1

        });

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