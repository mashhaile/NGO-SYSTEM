const Project = require("../../models/Project");

const {
    getBudgetFigures,
    approvedTotalsByCurrency,
    formatTotals
} = require("../budgetFigures");

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
    // BUDGETS (from the Budgets module only)
    // =================================================

    const figures =
        (await getBudgetFigures(
            organizationId,
            { projectIds: projects.map(project => project._id) }
        )).projects;

    const figureOf = (project) =>
        figures[String(project._id || project.id)] || null;

    // Approved amount as a number (charts); currency kept separately
    const approvedOf = (project) =>
        figureOf(project)?.approvedAmount || 0;

    const money = (figure, amount) =>
        figure && figure.status === "Approved"
            ? formatTotals({ [figure.currency]: amount })
            : "-";


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

                    budgetCode:
                        figureOf(project)?.budgetCode || "-",

                    budgetStatus:
                        figureOf(project)?.status || "No budget",

                    approvedBudget:
                        money(figureOf(project), figureOf(project)?.approvedAmount),

                    spent:
                        money(figureOf(project), figureOf(project)?.spent),

                    remaining:
                        money(figureOf(project), figureOf(project)?.remaining),

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
                approvedOf(row);

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
                approvedOf(row);

        }
    );


    // =================================================
    // SUMMARY
    // =================================================

    // Per currency, e.g. "ETB 4,415,000.00" (approved budgets only)
    const totalBudget =
        formatTotals(
            approvedTotalsByCurrency(
                rows.map(figureOf)
            )
        );

    const projectsWithApprovedBudget =
        rows.filter(row => approvedOf(row) > 0).length;


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

            projectsWithApprovedBudget:
                projectsWithApprovedBudget,

            projectsWithoutApprovedBudget:
                totalProjects - projectsWithApprovedBudget,

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