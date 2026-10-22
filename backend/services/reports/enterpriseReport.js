const Enterprise =
    require("../../models/Enterprise");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const EnterpriseMember =
    require("../../models/EnterpriseMember");

const Enrollment =
    require("../../models/enrollment");

const Program =
    require("../../models/program");

const Project =
    require("../../models/Project");

const ServiceDelivery =
    require("../../models/ServiceDelivery");

const {
    roundMoney,
    findMemberDeliveryScope,
    expandToMembers
} = require("./beneficiaryShares");


// =====================================================
// BUILD REPORT DATE RANGE
// Supports:
// - custom dates
// - monthly
// - quarterly
// - semiannual / sixmonthly
// - annual / yearly
// - year
// =====================================================

const buildDateRange = (filters = {}) => {

    let startDate = null;
    let endDate = null;


    // =================================================
    // EXPLICIT DATES
    // =================================================

    if (filters.startDate) {

        startDate =
            new Date(filters.startDate);

    }

    if (filters.endDate) {

        endDate =
            new Date(filters.endDate);

        // Make end date inclusive
        endDate.setHours(
            23,
            59,
            59,
            999
        );

    }


    // =================================================
    // YEAR
    // =================================================

    if (
        filters.year &&
        !filters.startDate &&
        !filters.endDate
    ) {

        const year =
            Number(filters.year);

        if (!Number.isNaN(year)) {

            startDate =
                new Date(
                    year,
                    0,
                    1
                );

            endDate =
                new Date(
                    year + 1,
                    0,
                    1
                );

        }

    }


    // =================================================
    // PERIOD
    // =================================================

    if (
        filters.period &&
        filters.year
    ) {

        const year =
            Number(filters.year);

        const period =
            String(
                filters.period
            ).toLowerCase();


        // ---------------------------------------------
        // MONTHLY
        // month = 1 - 12
        // ---------------------------------------------

        if (
            period === "monthly" &&
            filters.month
        ) {

            const month =
                Number(filters.month) - 1;

            startDate =
                new Date(
                    year,
                    month,
                    1
                );

            endDate =
                new Date(
                    year,
                    month + 1,
                    1
                );

        }


        // ---------------------------------------------
        // QUARTERLY
        // quarter = 1 - 4
        // ---------------------------------------------

        if (
            period === "quarterly" &&
            filters.quarter
        ) {

            const quarter =
                Number(filters.quarter);

            const month =
                (quarter - 1) * 3;

            startDate =
                new Date(
                    year,
                    month,
                    1
                );

            endDate =
                new Date(
                    year,
                    month + 3,
                    1
                );

        }


        // ---------------------------------------------
        // SIX MONTHLY / SEMIANNUAL
        // half = 1 or 2
        // ---------------------------------------------

        if (
            (
                period === "semiannual" ||
                period === "semi-annual" ||
                period === "sixmonthly" ||
                period === "six-monthly" ||
                period === "sixmonthly"
            ) &&
            filters.half
        ) {

            const half =
                Number(filters.half);


            if (half === 1) {

                startDate =
                    new Date(
                        year,
                        0,
                        1
                    );

                endDate =
                    new Date(
                        year,
                        6,
                        1
                    );

            }


            if (half === 2) {

                startDate =
                    new Date(
                        year,
                        6,
                        1
                    );

                endDate =
                    new Date(
                        year + 1,
                        0,
                        1
                    );

            }

        }


        // ---------------------------------------------
        // ANNUAL
        // ---------------------------------------------

        if (
            period === "annual" ||
            period === "yearly"
        ) {

            startDate =
                new Date(
                    year,
                    0,
                    1
                );

            endDate =
                new Date(
                    year + 1,
                    0,
                    1
                );

        }

    }


    return {
        startDate,
        endDate
    };

};


// =====================================================
// GENERATE ENTERPRISE PARTICIPATION REPORT
// =====================================================

const generate = async (

    filters = {},
    context

) => {


    // =================================================
    // VALIDATE CONTEXT
    // =================================================

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
    // DATE RANGE
    // =================================================

    const {
        startDate,
        endDate
    } =
        buildDateRange(
            filters
        );


    // =================================================
    // ENTERPRISE QUERY
    // =================================================

    const enterpriseQuery = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    if (filters.status) {

        enterpriseQuery.status =
            filters.status;

    }


    if (filters.enterpriseType) {

        enterpriseQuery.enterpriseType =
            filters.enterpriseType;

    }


    if (filters.ownershipType) {

        enterpriseQuery.ownershipType =
            filters.ownershipType;

    }


    if (filters.businessSector) {

        enterpriseQuery.businessSector =
            filters.businessSector;

    }


    if (filters.enterprise) {

        enterpriseQuery._id =
            filters.enterprise;

    }


    // =================================================
    // ENTERPRISES
    // =================================================

    const enterprises =
        await Enterprise.find(
            enterpriseQuery
        )
        .populate(
            "enterpriseType",
            "name value code"
        )
        .populate(
            "ownershipType",
            "name value code"
        )
        .populate(
            "businessSector",
            "name value code"
        )
        .sort({
            name: 1
        });


    const rows = [];


    // =================================================
    // PROCESS EACH ENTERPRISE
    // =================================================

    for (
        const enterprise
        of enterprises
    ) {


        // =============================================
        // ENTERPRISE MEMBERS
        // =============================================

        const memberQuery = {

            organization:
                organizationId,

            enterprise:
                enterprise._id,

            isDeleted:
                false

        };


        if (filters.memberStatus) {

            memberQuery.status =
                filters.memberStatus;

        }


        // Membership date filter
        if (startDate || endDate) {

            memberQuery.joinedDate = {};

            if (startDate) {

                memberQuery.joinedDate.$gte =
                    startDate;

            }

            if (endDate) {

                memberQuery.joinedDate.$lt =
                    endDate;

            }

        }


        const members =
            await EnterpriseMember.find(
                memberQuery
            )
            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName"
            );


        // =============================================
        // BENEFICIARY IDS
        // =============================================

        const beneficiaryIds =
            members
                .map(
                    member =>
                        member.beneficiary?._id
                )
                .filter(Boolean);


        // =============================================
        // MEMBER ROWS
        // =============================================

        const memberRows =
            members.map(
                member => ({

                    id:
                        member._id,

                    beneficiary:
                        member.beneficiary
                            ? {

                                id:
                                    member.beneficiary._id,

                                beneficiaryNumber:
                                    member.beneficiary.beneficiaryNumber,

                                name:
                                    [
                                        member.beneficiary.firstName,
                                        member.beneficiary.middleName,
                                        member.beneficiary.lastName
                                    ]
                                    .filter(Boolean)
                                    .join(" ")

                            }
                            : null,

                    memberRole:
                        member.memberRole,

                    joinedDate:
                        member.joinedDate,

                    leftDate:
                        member.leftDate,

                    status:
                        member.status

                })
            );


        // =============================================
        // NO BENEFICIARIES
        // =============================================

        if (!beneficiaryIds.length) {

            rows.push({

                enterprise: {

                    id:
                        enterprise._id,

                    enterpriseNumber:
                        enterprise.enterpriseNumber,

                    name:
                        enterprise.name,

                    description:
                        enterprise.description,

                    enterpriseType:
                        enterprise.enterpriseType,

                    ownershipType:
                        enterprise.ownershipType,

                    businessSector:
                        enterprise.businessSector,

                    status:
                        enterprise.status,

                    startDate:
                        enterprise.startDate,

                    endDate:
                        enterprise.endDate

                },

                totals: {

                    members:
                        members.length,

                    activeMembers:
                        members.filter(
                            member =>
                                member.status ===
                                "Active"
                        ).length,

                    programs:
                        0,

                    projects:
                        0,

                    serviceDeliveries:
                        0,

                    services:
                        0,

                    totalSupport:
                        0

                },

                members:
                    memberRows,

                programs: []

            });

            continue;

        }


        // =============================================
        // SERVICE DELIVERIES
        //
        // This is the important connection:
        //
        // Enterprise
        //   ↓
        // Member
        //   ↓
        // Beneficiary
        //   ↓
        // ServiceDelivery
        // =============================================

        // Members are linked to deliveries through
        // ServiceDeliveryBeneficiary (old deliveries: on the delivery)
        const memberScope =
            await findMemberDeliveryScope(
                organizationId,
                beneficiaryIds
            );


        const serviceQuery = {

            organization:
                organizationId,

            ...memberScope.filter,

            isDeleted:
                false,
            ...COUNTED_DELIVERY_FILTER

        };


        if (filters.program) {

            serviceQuery.program =
                filters.program;

        }


        if (filters.project) {

            serviceQuery.project =
                filters.project;

        }


        if (startDate || endDate) {

            serviceQuery.deliveryDate = {};

            if (startDate) {

                serviceQuery.deliveryDate.$gte =
                    startDate;

            }

            if (endDate) {

                serviceQuery.deliveryDate.$lt =
                    endDate;

            }

        }


        const serviceDeliveriesFound =
            await ServiceDelivery.find(
                serviceQuery
            )
            .populate(
                "program",
                "programCode name status"
            )
            .populate(
                "project",
                "projectCode name status"
            )
            .populate(
                "activity",
                "name"
            )
            .populate(
                "activityRun",
                "name startDate endDate"
            )
            .populate(
                "fundingSource",
                "name value code"
            )
            .populate(
                "items.serviceCategory",
                "name value code"
            )
            .populate(
                "items.serviceType",
                "name value code"
            )
            .sort({
                deliveryDate: 1
            });


        // One row per member: the delivery as they received it
        const serviceDeliveries =
            await expandToMembers(
                organizationId,
                serviceDeliveriesFound,
                memberScope.links,
                beneficiaryIds
            );


        // =============================================
        // PROGRAM MAP
        // =============================================

        const programMap =
            new Map();


        // =============================================
        // SERVICE DELIVERY PROCESSING
        // =============================================

        for (
            const delivery
            of serviceDeliveries
        ) {

            const program =
                delivery.program;


            if (!program) {

                continue;

            }


            const programId =
                String(
                    program._id
                );


            // =========================================
            // CREATE PROGRAM
            // =========================================

            if (
                !programMap.has(
                    programId
                )
            ) {

                programMap.set(
                    programId,
                    {

                        id:
                            program._id,

                        programCode:
                            program.programCode,

                        name:
                            program.name,

                        status:
                            program.status,

                        projects:
                            new Map(),

                        totals: {

                            serviceDeliveries:
                                0,

                            services:
                                0,

                            totalSupport:
                                0

                        }

                    }
                );

            }


            const programData =
                programMap.get(
                    programId
                );


            // =========================================
            // PROGRAM TOTALS
            // =========================================

            programData.totals.serviceDeliveries++;

            programData.totals.totalSupport =
                roundMoney(programData.totals.totalSupport + Number(
                    delivery.totalAmount ||
                    0
                ));


            // =========================================
            // PROJECT
            // =========================================

            const project =
                delivery.project;


            let projectData = null;


            if (project) {

                const projectId =
                    String(
                        project._id
                    );


                if (
                    !programData.projects.has(
                        projectId
                    )
                ) {

                    programData.projects.set(
                        projectId,
                        {

                            id:
                                project._id,

                            projectCode:
                                project.projectCode,

                            name:
                                project.name,

                            status:
                                project.status,

                            startDate:
                                project.startDate,

                            endDate:
                                project.endDate,

                            activities:
                                new Map(),

                            totals: {

                                serviceDeliveries:
                                    0,

                                services:
                                    0,

                                totalSupport:
                                    0

                            }

                        }
                    );

                }


                projectData =
                    programData.projects.get(
                        projectId
                    );


                projectData.totals.serviceDeliveries++;

                projectData.totals.totalSupport =
                    roundMoney(projectData.totals.totalSupport + Number(
                        delivery.totalAmount ||
                        0
                    ));

            }


            // =========================================
            // ACTIVITY
            // =========================================

            let activityData = null;


            if (
                projectData &&
                delivery.activity
            ) {

                const activityId =
                    String(
                        delivery.activity._id
                    );


                if (
                    !projectData.activities.has(
                        activityId
                    )
                ) {

                    projectData.activities.set(
                        activityId,
                        {

                            id:
                                delivery.activity._id,

                            name:
                                delivery.activity.name,

                            activityRuns:
                                new Map(),

                            totals: {

                                serviceDeliveries:
                                    0,

                                services:
                                    0,

                                totalSupport:
                                    0

                            }

                        }
                    );

                }


                activityData =
                    projectData.activities.get(
                        activityId
                    );


                activityData.totals.serviceDeliveries++;

                activityData.totals.totalSupport =
                    roundMoney(activityData.totals.totalSupport + Number(
                        delivery.totalAmount ||
                        0
                    ));

            }


            // =========================================
            // ACTIVITY RUN
            // =========================================

            let activityRunData = null;


            if (
                activityData &&
                delivery.activityRun
            ) {

                const runId =
                    String(
                        delivery.activityRun._id
                    );


                if (
                    !activityData.activityRuns.has(
                        runId
                    )
                ) {

                    activityData.activityRuns.set(
                        runId,
                        {

                            id:
                                delivery.activityRun._id,

                            name:
                                delivery.activityRun.name,

                            startDate:
                                delivery.activityRun.startDate,

                            endDate:
                                delivery.activityRun.endDate,

                            totals: {

                                serviceDeliveries:
                                    0,

                                services:
                                    0,

                                totalSupport:
                                    0

                            }

                        }
                    );

                }


                activityRunData =
                    activityData.activityRuns.get(
                        runId
                    );


                activityRunData.totals.serviceDeliveries++;

                activityRunData.totals.totalSupport =
                    roundMoney(activityRunData.totals.totalSupport + Number(
                        delivery.totalAmount ||
                        0
                    ));

            }


            // =========================================
            // SERVICE ITEMS
            // =========================================

            for (
                const item
                of delivery.items || []
            ) {

                const quantity =
                    Number(
                        item.quantity ||
                        0
                    );


                programData.totals.services +=
                    quantity;


                if (projectData) {

                    projectData.totals.services +=
                        quantity;

                }


                if (activityData) {

                    activityData.totals.services +=
                        quantity;

                }


                if (activityRunData) {

                    activityRunData.totals.services +=
                        quantity;

                }

            }

        }


        // =============================================
        // CONVERT MAPS TO ARRAYS
        // =============================================

        const programs =
            Array.from(
                programMap.values()
            )
            .map(
                program => ({

                    id:
                        program.id,

                    programCode:
                        program.programCode,

                    name:
                        program.name,

                    status:
                        program.status,

                    totals:
                        program.totals,

                    projects:
                        Array.from(
                            program.projects.values()
                        )
                        .map(
                            project => ({

                                id:
                                    project.id,

                                projectCode:
                                    project.projectCode,

                                name:
                                    project.name,

                                status:
                                    project.status,

                                startDate:
                                    project.startDate,

                                endDate:
                                    project.endDate,

                                totals:
                                    project.totals,

                                activities:
                                    Array.from(
                                        project.activities.values()
                                    )
                                    .map(
                                        activity => ({

                                            id:
                                                activity.id,

                                            name:
                                                activity.name,

                                            totals:
                                                activity.totals,

                                            activityRuns:
                                                Array.from(
                                                    activity.activityRuns.values()
                                                )

                                        })
                                    )

                            })
                        )

                })
            );


        // =============================================
        // ENTERPRISE TOTALS
        // =============================================

        const totalServiceDeliveries =
            serviceDeliveries.length;


        const totalServices =
            serviceDeliveries.reduce(
                (
                    total,
                    delivery
                ) => {

                    return total +
                        (delivery.items || [])
                            .reduce(
                                (
                                    itemTotal,
                                    item
                                ) => {

                                    return itemTotal +
                                        Number(
                                            item.quantity ||
                                            0
                                        );

                                },
                                0
                            );

                },
                0
            );


        const totalSupport =
            roundMoney(serviceDeliveries.reduce(
                (
                    total,
                    delivery
                ) =>
                    total +
                    Number(
                        delivery.totalAmount ||
                        0
                    ),
                0
            ));


        const totalPrograms =
            programs.length;


        const totalProjects =
            new Set(

                programs.flatMap(
                    program =>
                        program.projects.map(
                            project =>
                                String(
                                    project.id
                                )
                        )
                )

            ).size;


        // =============================================
        // FINAL ENTERPRISE ROW
        // =============================================

        rows.push({

            enterprise: {

                id:
                    enterprise._id,

                enterpriseNumber:
                    enterprise.enterpriseNumber,

                name:
                    enterprise.name,

                description:
                    enterprise.description,

                enterpriseType:
                    enterprise.enterpriseType,

                ownershipType:
                    enterprise.ownershipType,

                businessSector:
                    enterprise.businessSector,

                status:
                    enterprise.status,

                startDate:
                    enterprise.startDate,

                endDate:
                    enterprise.endDate

            },

            totals: {

                members:
                    members.length,

                activeMembers:
                    members.filter(
                        member =>
                            member.status ===
                            "Active"
                    ).length,

                programs:
                    totalPrograms,

                projects:
                    totalProjects,

                serviceDeliveries:
                    totalServiceDeliveries,

                services:
                    totalServices,

                totalSupport:
                    totalSupport

            },

            members:
                memberRows,

            programs

        });

    }


    // =================================================
    // GLOBAL SUMMARY
    // =================================================

    const totalMembers =
        rows.reduce(
            (
                total,
                row
            ) =>
                total +
                row.totals.members,
            0
        );


    const totalActiveMembers =
        rows.reduce(
            (
                total,
                row
            ) =>
                total +
                row.totals.activeMembers,
            0
        );


    const totalServiceDeliveries =
        rows.reduce(
            (
                total,
                row
            ) =>
                total +
                row.totals.serviceDeliveries,
            0
        );


    const totalServices =
        rows.reduce(
            (
                total,
                row
            ) =>
                total +
                row.totals.services,
            0
        );


    const totalSupport =
        roundMoney(rows.reduce(
            (
                total,
                row
            ) =>
                total +
                row.totals.totalSupport,
            0
        ));


    const uniquePrograms =
        new Set();


    const uniqueProjects =
        new Set();


    rows.forEach(
        row => {

            row.programs.forEach(
                program => {

                    uniquePrograms.add(
                        String(
                            program.id
                        )
                    );


                    program.projects.forEach(
                        project => {

                            uniqueProjects.add(
                                String(
                                    project.id
                                )
                            );

                        }
                    );

                }
            );

        }
    );


    // =================================================
    // RETURN REPORT
    // =================================================

    return {

        report:
            "enterpriseReport",

        reportTitle:
            "Enterprise Participation and Support Report",

        generatedAt:
            new Date(),

        period: {

            startDate:
                startDate,

            endDate:
                endDate,

            year:
                filters.year ||
                null,

            period:
                filters.period ||
                null,

            month:
                filters.month ||
                null,

            quarter:
                filters.quarter ||
                null,

            half:
                filters.half ||
                null

        },

        summary: {

            totalEnterprises:
                rows.length,

            totalMembers:
                totalMembers,

            totalActiveMembers:
                totalActiveMembers,

            totalPrograms:
                uniquePrograms.size,

            totalProjects:
                uniqueProjects.size,

            totalServiceDeliveries:
                totalServiceDeliveries,

            totalServices:
                totalServices,

            totalSupport:
                totalSupport

        },

        data:
            rows

    };

};


module.exports = {

    generate

};