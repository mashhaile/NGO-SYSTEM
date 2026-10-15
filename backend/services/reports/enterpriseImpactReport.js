const Enterprise = require("../../models/Enterprise");
const EnterpriseMember = require("../../models/EnterpriseMember");
const ServiceDelivery = require("../../models/ServiceDelivery");


// =====================================================
// DATE FILTER
// =====================================================

const buildDeliveryDateFilter = (
    filters = {}
) => {

    let startDate = null;
    let endDate = null;


    // -------------------------------------------------
    // Explicit dates
    // -------------------------------------------------

    if (filters.startDate) {

        startDate =
            new Date(
                filters.startDate
            );

    }


    if (filters.endDate) {

        endDate =
            new Date(
                filters.endDate
            );

    }


    // -------------------------------------------------
    // Year
    // -------------------------------------------------

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


    // -------------------------------------------------
    // Reporting periods
    // -------------------------------------------------

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
        // SEMI ANNUAL / SIX MONTHLY
        // ---------------------------------------------

        if (
            (
                period === "semiannual" ||
                period === "semi-annual" ||
                period === "sixmonthly" ||
                period === "six-monthly"
            ) &&
            filters.half
        ) {

            const half =
                Number(filters.half);


            // H1
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


            // H2
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


    const filter = {};


    if (startDate || endDate) {

        filter.$gte =
            startDate ||
            new Date(0);

        filter.$lt =
            endDate ||
            new Date(
                "9999-12-31"
            );

    }


    return filter;

};


// =====================================================
// GENERATE ENTERPRISE IMPACT REPORT
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
    // ENTERPRISE QUERY
    // =================================================

    const enterpriseQuery = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    if (filters.enterprise) {

        enterpriseQuery._id =
            filters.enterprise;

    }


    if (filters.status) {

        enterpriseQuery.status =
            filters.status;

    }


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


    const deliveryDateFilter =
        buildDeliveryDateFilter(
            filters
        );


    const rows = [];


    // =================================================
    // PROCESS ENTERPRISES
    // =================================================

    for (
        const enterprise
        of enterprises
    ) {


        // ---------------------------------------------
        // ENTERPRISE MEMBERS
        // ---------------------------------------------

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


        const members =
            await EnterpriseMember.find(
                memberQuery
            )
            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName"
            );


        const beneficiaryIds =
            members
                .map(
                    member =>
                        member.beneficiary?._id
                )
                .filter(Boolean);


        // ---------------------------------------------
        // NO MEMBERS
        // ---------------------------------------------

        if (!beneficiaryIds.length) {

            rows.push({

                enterprise: {

                    id:
                        enterprise._id,

                    enterpriseNumber:
                        enterprise.enterpriseNumber,

                    name:
                        enterprise.name,

                    enterpriseType:
                        enterprise.enterpriseType,

                    ownershipType:
                        enterprise.ownershipType,

                    businessSector:
                        enterprise.businessSector,

                    status:
                        enterprise.status

                },

                summary: {

                    beneficiaries:
                        0,

                    deliveries:
                        0,

                    programs:
                        0,

                    projects:
                        0,

                    activities:
                        0,

                    totalItems:
                        0,

                    totalSupportValue:
                        0

                },

                programs: [],

                projects: [],

                activities: [],

                services: []

            });

            continue;

        }


        // ---------------------------------------------
        // SERVICE DELIVERIES
        // ---------------------------------------------

        const serviceQuery = {

            organization:
                organizationId,

            beneficiary: {
                $in:
                    beneficiaryIds
            },

            isDeleted:
                false,

            status:
                "Delivered"

        };


        // ---------------------------------------------
        // PROGRAM FILTER
        // ---------------------------------------------

        if (filters.program) {

            serviceQuery.program =
                filters.program;

        }


        // ---------------------------------------------
        // PROJECT FILTER
        // ---------------------------------------------

        if (filters.project) {

            serviceQuery.project =
                filters.project;

        }


        // ---------------------------------------------
        // ACTIVITY FILTER
        // ---------------------------------------------

        if (filters.activity) {

            serviceQuery.activity =
                filters.activity;

        }


        // ---------------------------------------------
        // DELIVERY DATE
        // ---------------------------------------------

        if (
            Object.keys(
                deliveryDateFilter
            ).length
        ) {

            serviceQuery.deliveryDate =
                deliveryDateFilter;

        }


        const deliveries =
            await ServiceDelivery.find(
                serviceQuery
            )
            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName"
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
                "activityCode name status"
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
                deliveryDate:
                    -1
            });


        // =================================================
        // BUILD SERVICE ROWS
        // =================================================

        const serviceRows = [];


        for (
            const delivery
            of deliveries
        ) {

            const member =
                members.find(
                    item =>
                        item.beneficiary &&
                        String(
                            item.beneficiary._id
                        ) ===
                        String(
                            delivery.beneficiary?._id
                        )
                );


            // ---------------------------------------------
            // ITEMS
            // ---------------------------------------------

            const items =
                (delivery.items || [])
                    .map(
                        item => ({

                            serviceCategory:
                                item.serviceCategory
                                    ? {

                                        id:
                                            item.serviceCategory._id,

                                        name:
                                            item.serviceCategory.name,

                                        value:
                                            item.serviceCategory.value,

                                        code:
                                            item.serviceCategory.code

                                    }
                                    : null,

                            serviceType:
                                item.serviceType
                                    ? {

                                        id:
                                            item.serviceType._id,

                                        name:
                                            item.serviceType.name,

                                        value:
                                            item.serviceType.value,

                                        code:
                                            item.serviceType.code

                                    }
                                    : null,

                            quantity:
                                Number(
                                    item.quantity || 0
                                ),

                            unit:
                                item.unit,

                            unitCost:
                                Number(
                                    item.unitCost || 0
                                ),

                            totalCost:
                                Number(
                                    item.totalCost || 0
                                ),

                            remarks:
                                item.remarks || ""

                        })
                    );


            serviceRows.push({

                deliveryId:
                    delivery._id,

                deliveryNumber:
                    delivery.deliveryNumber,

                deliveryDate:
                    delivery.deliveryDate,

                beneficiary:
                    delivery.beneficiary
                        ? {

                            id:
                                delivery.beneficiary._id,

                            beneficiaryNumber:
                                delivery.beneficiary.beneficiaryNumber,

                            name:
                                [
                                    delivery.beneficiary.firstName,
                                    delivery.beneficiary.middleName,
                                    delivery.beneficiary.lastName
                                ]
                                .filter(Boolean)
                                .join(" ")

                        }
                        : null,

                enterpriseMember:

                    member
                        ? {

                            id:
                                member._id,

                            memberRole:
                                member.memberRole,

                            status:
                                member.status,

                            joinedDate:
                                member.joinedDate,

                            leftDate:
                                member.leftDate

                        }
                        : null,

                program:
                    delivery.program
                        ? {

                            id:
                                delivery.program._id,

                            programCode:
                                delivery.program.programCode,

                            name:
                                delivery.program.name,

                            status:
                                delivery.program.status

                        }
                        : null,

                project:
                    delivery.project
                        ? {

                            id:
                                delivery.project._id,

                            projectCode:
                                delivery.project.projectCode,

                            name:
                                delivery.project.name,

                            status:
                                delivery.project.status

                        }
                        : null,

                activity:
                    delivery.activity
                        ? {

                            id:
                                delivery.activity._id,

                            name:
                                delivery.activity.name,

                            status:
                                delivery.activity.status

                        }
                        : null,

                activityRun:
                    delivery.activityRun
                        ? {

                            id:
                                delivery.activityRun._id,

                            name:
                                delivery.activityRun.name,

                            startDate:
                                delivery.activityRun.startDate,

                            endDate:
                                delivery.activityRun.endDate

                        }
                        : null,

                fundingSource:
                    delivery.fundingSource
                        ? {

                            id:
                                delivery.fundingSource._id,

                            name:
                                delivery.fundingSource.name,

                            value:
                                delivery.fundingSource.value,

                            code:
                                delivery.fundingSource.code

                        }
                        : null,

                recipientType:
                    delivery.recipientType,

                deliveryLocation:
                    delivery.deliveryLocation,

                items,

                totalAmount:
                    Number(
                        delivery.totalAmount || 0
                    )

            });

        }


        // =================================================
        // UNIQUE PROGRAMS
        // =================================================

        const programs =
            new Map();


        serviceRows.forEach(
            row => {

                if (
                    row.program &&
                    row.program.id
                ) {

                    programs.set(
                        String(
                            row.program.id
                        ),
                        row.program
                    );

                }

            }
        );


        // =================================================
        // UNIQUE PROJECTS
        // =================================================

        const projects =
            new Map();


        serviceRows.forEach(
            row => {

                if (
                    row.project &&
                    row.project.id
                ) {

                    projects.set(
                        String(
                            row.project.id
                        ),
                        row.project
                    );

                }

            }
        );


        // =================================================
        // UNIQUE ACTIVITIES
        // =================================================

        const activities =
            new Map();


        serviceRows.forEach(
            row => {

                if (
                    row.activity &&
                    row.activity.id
                ) {

                    activities.set(
                        String(
                            row.activity.id
                        ),
                        row.activity
                    );

                }

            }
        );


        // =================================================
        // TOTALS
        // =================================================

        const totalItems =
            serviceRows.reduce(

                (
                    total,
                    service
                ) => {

                    return total +
                        service.items.reduce(
                            (
                                itemTotal,
                                item
                            ) =>
                                itemTotal +
                                Number(
                                    item.quantity || 0
                                ),
                            0
                        );

                },

                0

            );


        const totalSupportValue =
            serviceRows.reduce(

                (
                    total,
                    service
                ) =>
                    total +
                    Number(
                        service.totalAmount || 0
                    ),

                0

            );


        // =================================================
        // PUSH ENTERPRISE
        // =================================================

        rows.push({

            enterprise: {

                id:
                    enterprise._id,

                enterpriseNumber:
                    enterprise.enterpriseNumber,

                name:
                    enterprise.name,

                enterpriseType:
                    enterprise.enterpriseType,

                ownershipType:
                    enterprise.ownershipType,

                businessSector:
                    enterprise.businessSector,

                status:
                    enterprise.status

            },

            summary: {

                beneficiaries:
                    new Set(
                        serviceRows
                            .map(
                                service =>
                                    service.beneficiary?.id
                            )
                            .filter(Boolean)
                            .map(
                                id =>
                                    String(id)
                            )
                    ).size,

                deliveries:
                    serviceRows.length,

                programs:
                    programs.size,

                projects:
                    projects.size,

                activities:
                    activities.size,

                totalItems,

                totalSupportValue

            },

            programs:
                Array.from(
                    programs.values()
                ),

            projects:
                Array.from(
                    projects.values()
                ),

            activities:
                Array.from(
                    activities.values()
                ),

            services:
                serviceRows

        });

    }


    // =================================================
    // GLOBAL SUMMARY
    // =================================================

    return {

        report:
            "enterpriseImpactReport",

        reportTitle:
            "Enterprise Impact and Support Report",

        generatedAt:
            new Date(),

        period: {

            startDate:
                filters.startDate ||
                null,

            endDate:
                filters.endDate ||
                null,

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

            totalDeliveries:
                rows.reduce(
                    (
                        total,
                        row
                    ) =>
                        total +
                        row.summary.deliveries,
                    0
                ),

            totalBeneficiaries:
                new Set(
                    rows.flatMap(
                        row =>
                            row.services
                                .map(
                                    service =>
                                        service.beneficiary?.id
                                )
                                .filter(Boolean)
                                .map(
                                    id =>
                                        String(id)
                                )
                    )
                ).size,

            totalPrograms:
                new Set(
                    rows.flatMap(
                        row =>
                            row.programs
                                .map(
                                    program =>
                                        String(
                                            program.id
                                        )
                                )
                    )
                ).size,

            totalProjects:
                new Set(
                    rows.flatMap(
                        row =>
                            row.projects
                                .map(
                                    project =>
                                        String(
                                            project.id
                                        )
                                )
                    )
                ).size,

            totalActivities:
                new Set(
                    rows.flatMap(
                        row =>
                            row.activities
                                .map(
                                    activity =>
                                        String(
                                            activity.id
                                        )
                                )
                    )
                ).size,

            totalItems:
                rows.reduce(
                    (
                        total,
                        row
                    ) =>
                        total +
                        row.summary.totalItems,
                    0
                ),

            totalSupportValue:
                rows.reduce(
                    (
                        total,
                        row
                    ) =>
                        total +
                        row.summary.totalSupportValue,
                    0
                )

        },

        data:
            rows

    };

};


module.exports = {

    generate

};