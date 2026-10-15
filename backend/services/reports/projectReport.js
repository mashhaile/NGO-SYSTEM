const Project = require("../../models/Project");

const {
    buildDateFilter
} = require("./reportFilters");


// =====================================================
// GENERATE PROJECT REPORT
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
    // STATUS FILTER
    // =================================================

    if (filters.status) {

        query.status =
            filters.status;

    }


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
    // PROJECTS
    // =================================================

    const projects =
        await Project.find(query)

            .populate(
                {
                    path: "program",
                    select: "programCode name status"
                }
            )

            .populate(
                {
                    path: "donor",
                    select: "name donorType country website registrationNumber"
                }
            )

            .populate(
                {
                    path: "projectManager",
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
        projects.map(
            project => {

                const managerName =
                    project.projectManager
                        ? [
                            project.projectManager.firstName,
                            project.projectManager.middleName,
                            project.projectManager.lastName
                        ]
                            .filter(Boolean)
                            .join(" ")
                        : null;


                return {

                    id:
                        project._id,

                    projectCode:
                        project.projectCode,

                    name:
                        project.name,

                    description:
                        project.description,

                    program:
                        project.program
                            ? {

                                id:
                                    project.program._id,

                                programCode:
                                    project.program.programCode,

                                name:
                                    project.program.name,

                                status:
                                    project.program.status

                            }
                            : null,

                    donor:
                        project.donor
                            ? {

                                id:
                                    project.donor._id,

                                name:
                                    project.donor.name,

                                donorType:
                                    project.donor.donorType,

                                country:
                                    project.donor.country,

                                website:
                                    project.donor.website,

                                registrationNumber:
                                    project.donor.registrationNumber

                            }
                            : null,

                    projectManager:
                        project.projectManager
                            ? {

                                id:
                                    project.projectManager._id,

                                name:
                                    managerName,

                                email:
                                    project.projectManager.email

                            }
                            : null,

                    approvedBudget:
                        Number(
                            project.approvedBudget || 0
                        ),

                    startDate:
                        project.startDate,

                    endDate:
                        project.endDate,

                    status:
                        project.status

                };

            }
        );


    // =================================================
    // STATUS SUMMARY
    // =================================================

    const statusSummary = {};


    rows.forEach(
        row => {

            statusSummary[row.status] =
                (
                    statusSummary[row.status] ||
                    0
                ) + 1;

        }
    );


    // =================================================
    // PROGRAM SUMMARY
    // =================================================

    const programSummary = {};


    rows.forEach(
        row => {

            if (!row.program) {

                return;

            }


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

                    projects:
                        0,

                    approvedBudget:
                        0

                };

            }


            programSummary[programId].projects +=
                1;


            programSummary[programId].approvedBudget +=
                Number(
                    row.approvedBudget || 0
                );

        }
    );


    // =================================================
    // DONOR SUMMARY
    // =================================================

    const donorSummary = {};


    rows.forEach(
        row => {

            if (!row.donor) {

                return;

            }


            const donorId =
                String(
                    row.donor.id
                );


            if (
                !donorSummary[donorId]
            ) {

                donorSummary[donorId] = {

                    donorId:
                        row.donor.id,

                    donor:
                        row.donor.name,

                    donorType:
                        row.donor.donorType,

                    country:
                        row.donor.country,

                    projects:
                        0,

                    approvedBudget:
                        0

                };

            }


            donorSummary[donorId].projects +=
                1;


            donorSummary[donorId].approvedBudget +=
                Number(
                    row.approvedBudget || 0
                );

        }
    );


    // =================================================
    // SUMMARY
    // =================================================

    const totalBudget =
        rows.reduce(
            (
                sum,
                row
            ) => {

                return (
                    sum +
                    Number(
                        row.approvedBudget || 0
                    )
                );

            },
            0
        );


    const totalProjects =
        rows.length;


    const projectsWithDonor =
        rows.filter(
            row =>
                Boolean(
                    row.donor
                )
        ).length;


    const projectsWithoutDonor =
        totalProjects -
        projectsWithDonor;


    const projectsWithProgram =
        rows.filter(
            row =>
                Boolean(
                    row.program
                )
        ).length;


    const projectsWithoutProgram =
        totalProjects -
        projectsWithProgram;


    // =================================================
    // RESPONSE
    // =================================================

    return {

        report:
            "projectReport",

        reportTitle:
            "Project Report",

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

            totalProjects:
                totalProjects,

            totalApprovedBudget:
                totalBudget,

            projectsWithProgram:
                projectsWithProgram,

            projectsWithoutProgram:
                projectsWithoutProgram,

            projectsWithDonor:
                projectsWithDonor,

            projectsWithoutDonor:
                projectsWithoutDonor,

            status:
                statusSummary

        },

        charts: {

            projectsByStatus:
                Object.entries(
                    statusSummary
                ).map(
                    (
                        [
                            status,
                            projects
                        ]
                    ) => ({

                        status:
                            status,

                        projects:
                            projects

                    })
                ),

            projectsByProgram:
                Object.values(
                    programSummary
                ),

            budgetByProgram:
                Object.values(
                    programSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        approvedBudget:
                            item.approvedBudget

                    })
                ),

            projectsByDonor:
                Object.values(
                    donorSummary
                ).map(
                    item => ({

                        donorId:
                            item.donorId,

                        donor:
                            item.donor,

                        donorType:
                            item.donorType,

                        country:
                            item.country,

                        projects:
                            item.projects

                    })
                ),

            budgetByDonor:
                Object.values(
                    donorSummary
                ).map(
                    item => ({

                        donorId:
                            item.donorId,

                        donor:
                            item.donor,

                        donorType:
                            item.donorType,

                        country:
                            item.country,

                        approvedBudget:
                            item.approvedBudget

                    })
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