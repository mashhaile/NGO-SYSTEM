const ActivityRun =
    require("../../models/ActivityRun");

const {
    buildDateFilter,
    applyLocationFilter
} = require("./reportFilters");


// =====================================================
// GENERATE ACTIVITY RUN REPORT
// =====================================================

const generate = async (
    filters = {},
    context
) => {

    if (
        !context ||
        !context.organizationId
    ) {

        throw new Error(
            "Report organization context is required."
        );

    }


    const organizationId =
        context.organizationId;


    // =================================================
    // QUERY
    // =================================================

    const query = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // PROGRAM FILTER
    // =================================================

    if (filters.program) {

        query.program =
            filters.program;

    }


    // =================================================
    // PROJECT FILTER
    // =================================================

    if (filters.project) {

        query.project =
            filters.project;

    }


    // =================================================
    // ACTIVITY FILTER
    // =================================================

    if (filters.activity) {

        query.activity =
            filters.activity;

    }


    // =================================================
    // STATUS FILTER
    // =================================================

    if (filters.status) {

        query.status =
            filters.status;

    }


    // =================================================
    // LOCATION FILTER
    // =================================================

    applyLocationFilter(
        query,
        filters
    );


    // =================================================
    // DATE FILTER
    // =================================================

    const dateFilter =
        buildDateFilter(filters);


    if (
        Object.keys(dateFilter).length
    ) {

        query.startDate =
            dateFilter;

    }


    // =================================================
    // ACTIVITY RUNS
    // =================================================

    const runs =
        await ActivityRun.find(query)

            .populate(
                {
                    path: "program",
                    select: "programCode name status"
                }
            )

            .populate(
                {
                    path: "project",
                    select: "projectCode name status"
                }
            )

            .populate(
                {
                    path: "activity",
                    select: "activityCode name activityType status"
                }
            )

            .populate(
                {
                    path: "trainer",
                    select: "firstName middleName lastName email"
                }
            )

            .sort(
                {
                    startDate: -1,
                    name: 1
                }
            );


    // =================================================
    // ROWS
    // =================================================

    const rows =
        runs.map(
            run => {

                const trainerName =
                    run.trainer
                        ? [
                            run.trainer.firstName,
                            run.trainer.middleName,
                            run.trainer.lastName
                        ]
                            .filter(Boolean)
                            .join(" ")
                        : null;


                return {

                    id:
                        run._id,

                    runCode:
                        run.runCode,

                    name:
                        run.name,

                    startDate:
                        run.startDate,

                    endDate:
                        run.endDate,

                    region:
                        run.region,

                    zone:
                        run.zone,

                    woreda:
                        run.woreda,

                    location:
                        run.location,

                    targetGroup:
                        run.targetGroup,

                    status:
                        run.status,

                    notes:
                        run.notes,

                    program:
                        run.program
                            ? {

                                id:
                                    run.program._id,

                                programCode:
                                    run.program.programCode,

                                name:
                                    run.program.name,

                                status:
                                    run.program.status

                            }
                            : null,

                    project:
                        run.project
                            ? {

                                id:
                                    run.project._id,

                                projectCode:
                                    run.project.projectCode,

                                name:
                                    run.project.name,

                                status:
                                    run.project.status

                            }
                            : null,

                    activity:
                        run.activity
                            ? {

                                id:
                                    run.activity._id,

                                activityCode:
                                    run.activity.activityCode,

                                name:
                                    run.activity.name,

                                activityType:
                                    run.activity.activityType,

                                status:
                                    run.activity.status

                            }
                            : null,

                    trainer:
                        run.trainer
                            ? {

                                id:
                                    run.trainer._id,

                                name:
                                    trainerName,

                                email:
                                    run.trainer.email

                            }
                            : null

                };

            }
        );


    // =================================================
    // SUMMARIES
    // =================================================

    const statusSummary = {};

    const targetGroupSummary = {};

    const programSummary = {};

    const projectSummary = {};

    const activitySummary = {};

    let runsWithTrainer = 0;

    let runsWithoutTrainer = 0;


    rows.forEach(
        row => {

            // -----------------------------------------
            // STATUS
            // -----------------------------------------

            statusSummary[row.status] =
                (
                    statusSummary[row.status] ||
                    0
                ) + 1;


            // -----------------------------------------
            // TARGET GROUP
            // -----------------------------------------

            if (
                row.targetGroup
            ) {

                targetGroupSummary[
                    row.targetGroup
                ] =
                    (
                        targetGroupSummary[
                            row.targetGroup
                        ] ||
                        0
                    ) + 1;

            }


            // -----------------------------------------
            // TRAINER
            // -----------------------------------------

            if (
                row.trainer
            ) {

                runsWithTrainer +=
                    1;

            } else {

                runsWithoutTrainer +=
                    1;

            }


            // -----------------------------------------
            // PROGRAM
            // -----------------------------------------

            if (
                row.program
            ) {

                const programId =
                    String(
                        row.program.id
                    );


                if (
                    !programSummary[programId]
                ) {

                    programSummary[programId] = {

                        programId:
                            row.program.id,

                        programCode:
                            row.program.programCode,

                        program:
                            row.program.name,

                        status:
                            row.program.status,

                        runs:
                            0

                    };

                }


                programSummary[programId].runs +=
                    1;

            }


            // -----------------------------------------
            // PROJECT
            // -----------------------------------------

            if (
                row.project
            ) {

                const projectId =
                    String(
                        row.project.id
                    );


                if (
                    !projectSummary[projectId]
                ) {

                    projectSummary[projectId] = {

                        projectId:
                            row.project.id,

                        projectCode:
                            row.project.projectCode,

                        project:
                            row.project.name,

                        status:
                            row.project.status,

                        runs:
                            0

                    };

                }


                projectSummary[projectId].runs +=
                    1;

            }


            // -----------------------------------------
            // ACTIVITY
            // -----------------------------------------

            if (
                row.activity
            ) {

                const activityId =
                    String(
                        row.activity.id
                    );


                if (
                    !activitySummary[activityId]
                ) {

                    activitySummary[activityId] = {

                        activityId:
                            row.activity.id,

                        activityCode:
                            row.activity.activityCode,

                        activity:
                            row.activity.name,

                        activityType:
                            row.activity.activityType,

                        status:
                            row.activity.status,

                        runs:
                            0

                    };

                }


                activitySummary[activityId].runs +=
                    1;

            }

        }
    );


    // =================================================
    // RESPONSE
    // =================================================

    return {

        report:
            "activityRunReport",

        reportTitle:
            "Activity Run Report",

        generatedAt:
            new Date(),

        period: {

            startDate:
                filters.startDate || null,

            endDate:
                filters.endDate || null,

            year:
                filters.year || null,

            period:
                filters.period || null,

            month:
                filters.month || null,

            quarter:
                filters.quarter || null,

            half:
                filters.half || null

        },

        summary: {

            totalRuns:
                rows.length,

            runsWithTrainer:
                runsWithTrainer,

            runsWithoutTrainer:
                runsWithoutTrainer,

            programsWithRuns:
                Object.keys(
                    programSummary
                ).length,

            projectsWithRuns:
                Object.keys(
                    projectSummary
                ).length,

            activitiesWithRuns:
                Object.keys(
                    activitySummary
                ).length,

            status:
                statusSummary,

            targetGroups:
                targetGroupSummary

        },

        charts: {

            runsByStatus:
                Object.entries(
                    statusSummary
                ).map(
                    (
                        [
                            status,
                            runs
                        ]
                    ) => ({

                        status:
                            status,

                        runs:
                            runs

                    })
                ),

            runsByTargetGroup:
                Object.entries(
                    targetGroupSummary
                ).map(
                    (
                        [
                            targetGroup,
                            runs
                        ]
                    ) => ({

                        targetGroup:
                            targetGroup,

                        runs:
                            runs

                    })
                ),

            runsByProgram:
                Object.values(
                    programSummary
                ),

            runsByProject:
                Object.values(
                    projectSummary
                ),

            runsByActivity:
                Object.values(
                    activitySummary
                )

        },

        details:
            rows,

        data:
            rows

    };

};


module.exports = {

    generate

};