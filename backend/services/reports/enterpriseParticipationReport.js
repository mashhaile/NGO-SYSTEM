const Enterprise = require("../../models/Enterprise");
const EnterpriseMember = require("../../models/EnterpriseMember");
const Beneficiary = require("../../models/Beneficiary");
const Enrollment = require("../../models/enrollment");
const Program = require("../../models/program");
const Project = require("../../models/Project");
const Activity = require("../../models/Activity");
const ActivityRun = require("../../models/ActivityRun");
const ServiceDelivery = require("../../models/ServiceDelivery");

const {
    roundMoney,
    findMemberDeliveryScope,
    expandToMembers
} = require("./beneficiaryShares");
const Lookup = require("../../models/Lookup");


// =====================================================
// BUILD DATE RANGE
// =====================================================

const buildPeriod = (filters = {}) => {

    let startDate = null;
    let endDate = null;

    const year =
        Number(filters.year) ||
        new Date().getFullYear();

    switch (filters.period) {

        case "monthly": {

            const month =
                Number(filters.month);

            if (!month || month < 1 || month > 12) {
                throw new Error(
                    "Month is required for monthly report."
                );
            }

            startDate =
                new Date(year, month - 1, 1);

            endDate =
                new Date(year, month, 0, 23, 59, 59, 999);

            break;
        }


        case "quarterly": {

            const quarter =
                Number(filters.quarter);

            if (
                !quarter ||
                quarter < 1 ||
                quarter > 4
            ) {
                throw new Error(
                    "Quarter must be between 1 and 4."
                );
            }

            const startMonth =
                (quarter - 1) * 3;

            startDate =
                new Date(
                    year,
                    startMonth,
                    1
                );

            endDate =
                new Date(
                    year,
                    startMonth + 3,
                    0,
                    23,
                    59,
                    59,
                    999
                );

            break;
        }


        case "sixMonthly": {

            const half =
                Number(filters.half);

            if (
                !half ||
                half < 1 ||
                half > 2
            ) {
                throw new Error(
                    "Half must be 1 or 2."
                );
            }

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
                        0,
                        23,
                        59,
                        59,
                        999
                    );

            } else {

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
                        0,
                        23,
                        59,
                        59,
                        999
                    );

            }

            break;
        }


        case "annual": {

            startDate =
                new Date(
                    year,
                    0,
                    1
                );

            endDate =
                new Date(
                    year,
                    11,
                    31,
                    23,
                    59,
                    59,
                    999
                );

            break;
        }


        case "custom": {

            if (!filters.startDate) {

                throw new Error(
                    "startDate is required for custom period."
                );

            }

            startDate =
                new Date(
                    filters.startDate
                );

            endDate =
                filters.endDate
                    ? new Date(filters.endDate)
                    : new Date(filters.startDate);

            endDate.setHours(
                23,
                59,
                59,
                999
            );

            break;
        }


        default: {

            if (
                filters.startDate ||
                filters.endDate
            ) {

                startDate =
                    filters.startDate
                        ? new Date(filters.startDate)
                        : null;

                endDate =
                    filters.endDate
                        ? new Date(filters.endDate)
                        : null;

                if (endDate) {

                    endDate.setHours(
                        23,
                        59,
                        59,
                        999
                    );

                }

            }

        }

    }


    return {
        startDate,
        endDate
    };

};


// =====================================================
// MAIN REPORT
// =====================================================

const generate = async (

    filters = {},

    context

) => {

    if (!context?.organizationId) {

        throw new Error(
            "Organization context is required."
        );

    }


    const organizationId =
        context.organizationId;


    const {
        startDate,
        endDate
    } =
        buildPeriod(filters);


    // =================================================
    // ENTERPRISE FILTER
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
        })
        .lean();


    if (!enterprises.length) {

        return {

            summary: {

                totalEnterprises: 0,

                totalBeneficiaries: 0,

                totalPrograms: 0,

                totalProjects: 0,

                totalActivities: 0,

                totalServiceDeliveries: 0,

                totalQuantity: 0,

                totalSupportValue: 0

            },

            period: {

                startDate,

                endDate

            },

            data: []

        };

    }


    const enterpriseIds =
        enterprises.map(
            enterprise =>
                enterprise._id
        );


    // =================================================
    // ENTERPRISE MEMBERS
    // =================================================

    const memberQuery = {

        organization:
            organizationId,

        enterprise: {
            $in:
                enterpriseIds
        },

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
            "beneficiaryNumber firstName middleName lastName gender"
        )
        .lean();


    if (!members.length) {

        return {

            summary: {

                totalEnterprises:
                    enterprises.length,

                totalBeneficiaries: 0,

                totalPrograms: 0,

                totalProjects: 0,

                totalActivities: 0,

                totalServiceDeliveries: 0,

                totalQuantity: 0,

                totalSupportValue: 0

            },

            period: {

                startDate,

                endDate

            },

            data: enterprises.map(
                enterprise => ({

                    enterprise: {

                        _id:
                            enterprise._id,

                        enterpriseNumber:
                            enterprise.enterpriseNumber,

                        name:
                            enterprise.name

                    },

                    programs: [],

                    summary: {

                        beneficiaries: 0,

                        programs: 0,

                        projects: 0,

                        services: 0,

                        quantity: 0,

                        supportValue: 0

                    }

                })
            )

        };

    }


    const beneficiaryIds =
        members.map(
            member =>
                member.beneficiary?._id
        )
        .filter(Boolean);


    // =================================================
    // ENROLLMENTS
    // =================================================

    const enrollmentQuery = {

        organization:
            organizationId,

        beneficiary: {
            $in:
                beneficiaryIds
        },

        isDeleted:
            false

    };


    if (filters.program) {

        enrollmentQuery.program =
            filters.program;

    }


    const enrollments =
        await Enrollment.find(
            enrollmentQuery
        )
        .populate(
            "program",
            "programCode name category startDate endDate status"
        )
        .lean();


    const enrollmentIds =
        enrollments.map(
            enrollment =>
                enrollment._id
        );


    const programIds =
        enrollments.map(
            enrollment =>
                enrollment.program?._id
        )
        .filter(Boolean);


    // =================================================
    // SERVICE DELIVERIES
    // =================================================

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

        status:
            "Delivered"

    };


    if (startDate || endDate) {

        serviceQuery.deliveryDate = {};

        if (startDate) {

            serviceQuery.deliveryDate.$gte =
                startDate;

        }

        if (endDate) {

            serviceQuery.deliveryDate.$lte =
                endDate;

        }

    }


    if (filters.program) {

        serviceQuery.program =
            filters.program;

    }


    if (filters.project) {

        serviceQuery.project =
            filters.project;

    }


    if (filters.activity) {

        serviceQuery.activity =
            filters.activity;

    }


    const servicesFound =
        await ServiceDelivery.find(
            serviceQuery
        )
        .populate(
            "program",
            "programCode name"
        )
        .populate(
            "project",
            "projectCode name"
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
            "beneficiary",
            "beneficiaryNumber firstName middleName lastName"
        )
        .populate(
            "enrollment",
            "status enrollmentDate"
        )
        .populate(
            "items.serviceCategory",
            "name value code"
        )
        .populate(
            "items.serviceType",
            "name value code"
        )
        .populate(
            "fundingSource",
            "name value code"
        )
        .lean();


    // One row per member: the delivery as they received it
    const services =
        await expandToMembers(
            organizationId,
            servicesFound,
            memberScope.links,
            beneficiaryIds
        );


    // =================================================
    // BUILD ENTERPRISE LOOKUP
    // =================================================

    const enterpriseMap =
        new Map();


    enterprises.forEach(
        enterprise => {

            enterpriseMap.set(
                String(enterprise._id),
                {

                    enterprise: {

                        _id:
                            enterprise._id,

                        enterpriseNumber:
                            enterprise.enterpriseNumber,

                        name:
                            enterprise.name,

                        status:
                            enterprise.status,

                        enterpriseType:
                            enterprise.enterpriseType,

                        ownershipType:
                            enterprise.ownershipType,

                        businessSector:
                            enterprise.businessSector

                    },

                    programs: [],

                    summary: {

                        beneficiaries: 0,

                        programs: 0,

                        projects: 0,

                        activities: 0,

                        services: 0,

                        quantity: 0,

                        supportValue: 0

                    }

                }
            );

        }
    );


    // =================================================
    // ADD PROGRAM PARTICIPATION
    // =================================================

    const programMaps =
        new Map();


    members.forEach(
        member => {

            if (!member.beneficiary) {

                return;

            }


            const enterpriseData =
                enterpriseMap.get(
                    String(member.enterprise)
                );


            if (!enterpriseData) {

                return;

            }


            const beneficiaryId =
                String(
                    member.beneficiary._id
                );


            const beneficiaryEnrollments =
                enrollments.filter(
                    enrollment =>
                        String(
                            enrollment.beneficiary
                        ) === beneficiaryId
                );


            beneficiaryEnrollments.forEach(
                enrollment => {

                    if (!enrollment.program) {

                        return;

                    }


                    const programId =
                        String(
                            enrollment.program._id
                        );


                    let programData =
                        enterpriseData.programs.find(
                            program =>
                                String(
                                    program.program._id
                                ) === programId
                        );


                    if (!programData) {

                        programData = {

                            program:
                                enrollment.program,

                            beneficiaries: [],

                            projects: [],

                            services: [],

                            summary: {

                                beneficiaries: 0,

                                projects: 0,

                                services: 0,

                                quantity: 0,

                                supportValue: 0

                            }

                        };


                        enterpriseData.programs.push(
                            programData
                        );

                    }


                    const alreadyAdded =
                        programData.beneficiaries.some(
                            beneficiary =>
                                String(
                                    beneficiary.beneficiary
                                ) === beneficiaryId
                        );


                    if (!alreadyAdded) {

                        programData.beneficiaries.push({

                            beneficiary:
                                member.beneficiary,

                            memberRole:
                                member.memberRole,

                            membershipStatus:
                                member.status,

                            joinedDate:
                                member.joinedDate,

                            leftDate:
                                member.leftDate,

                            enrollment: {

                                _id:
                                    enrollment._id,

                                status:
                                    enrollment.status,

                                enrollmentDate:
                                    enrollment.enrollmentDate,

                                completionDate:
                                    enrollment.completionDate

                            }

                        });


                        programData.summary.beneficiaries++;

                        enterpriseData.summary.beneficiaries++;

                    }

                }
            );

        }
    );


    // =================================================
    // ADD SERVICE DELIVERY
    // =================================================

    services.forEach(
        service => {

            const beneficiaryId =
                String(
                    service.beneficiary?._id
                );


            const matchingMembers =
                members.filter(
                    member =>
                        String(
                            member.beneficiary?._id
                        ) === beneficiaryId
                );


            matchingMembers.forEach(
                member => {

                    const enterpriseData =
                        enterpriseMap.get(
                            String(
                                member.enterprise
                            )
                        );


                    if (!enterpriseData) {

                        return;

                    }


                    const programId =
                        String(
                            service.program?._id
                        );


                    let programData =
                        enterpriseData.programs.find(
                            program =>
                                String(
                                    program.program?._id
                                ) === programId
                        );


                    // ---------------------------------
                    // Service may exist even if
                    // enrollment is not present.
                    // ---------------------------------

                    if (!programData) {

                        programData = {

                            program:
                                service.program,

                            beneficiaries: [],

                            projects: [],

                            services: [],

                            summary: {

                                beneficiaries: 0,

                                projects: 0,

                                services: 0,

                                quantity: 0,

                                supportValue: 0

                            }

                        };


                        enterpriseData.programs.push(
                            programData
                        );

                    }


                    // ---------------------------------
                    // Project
                    // ---------------------------------

                    if (service.project) {

                        const projectExists =
                            programData.projects.some(
                                project =>
                                    String(
                                        project.project?._id
                                    ) ===
                                    String(
                                        service.project._id
                                    )
                            );


                        if (!projectExists) {

                            programData.projects.push({

                                project:
                                    service.project,

                                activities: []

                            });

                        }


                        const projectData =
                            programData.projects.find(
                                project =>
                                    String(
                                        project.project?._id
                                    ) ===
                                    String(
                                        service.project._id
                                    )
                            );


                        if (
                            service.activity &&
                            projectData
                        ) {

                            const activityExists =
                                projectData.activities.some(
                                    activity =>
                                        String(
                                            activity._id
                                        ) ===
                                        String(
                                            service.activity._id
                                        )
                                );


                            if (!activityExists) {

                                projectData.activities.push(
                                    service.activity
                                );

                            }

                        }

                    }


                    // ---------------------------------
                    // Service items
                    // ---------------------------------

                    service.items =
                        service.items || [];


                    const serviceRecord = {

                        _id:
                            service._id,

                        deliveryNumber:
                            service.deliveryNumber,

                        beneficiary:
                            service.beneficiary,

                        enrollment:
                            service.enrollment,

                        program:
                            service.program,

                        project:
                            service.project,

                        activity:
                            service.activity,

                        activityRun:
                            service.activityRun,

                        deliveryDate:
                            service.deliveryDate,

                        deliveryLocation:
                            service.deliveryLocation,

                        fundingSource:
                            service.fundingSource,

                        items:
                            service.items,

                        totalAmount:
                            Number(
                                service.totalAmount || 0
                            )

                    };


                    programData.services.push(
                        serviceRecord
                    );


                    const quantity =
                        service.items.reduce(
                            (
                                total,
                                item
                            ) =>
                                total +
                                (Number(item.quantity || 0) > 0 ? 1 : 0),
                            0
                        );


                    const supportValue =
                        Number(
                            service.totalAmount || 0
                        );


                    programData.summary.services++;

                    programData.summary.quantity +=
                        quantity;

                    programData.summary.supportValue =
                        roundMoney(programData.summary.supportValue + supportValue);


                    enterpriseData.summary.services++;

                    enterpriseData.summary.quantity +=
                        quantity;

                    enterpriseData.summary.supportValue =
                        roundMoney(enterpriseData.summary.supportValue + supportValue);

                }
            );

        }
    );


    // =================================================
    // FINALIZE PROJECT / ACTIVITY COUNTS
    // =================================================

    enterpriseMap.forEach(
        enterpriseData => {

            enterpriseData.programs.forEach(
                programData => {

                    programData.summary.projects =
                        programData.projects.length;


                    programData.summary.services =
                        programData.services.length;


                    enterpriseData.summary.projects +=
                        programData.projects.length;


                    const activityIds =
                        new Set();


                    programData.projects.forEach(
                        project => {

                            (
                                project.activities ||
                                []
                            ).forEach(
                                activity => {

                                    activityIds.add(
                                        String(
                                            activity._id
                                        )
                                    );

                                }
                            );

                        }
                    );


                    programData.summary.activities =
                        activityIds.size;


                    enterpriseData.summary.activities +=
                        activityIds.size;

                }
            );


            enterpriseData.summary.programs =
                enterpriseData.programs.length;

        }
    );


    // =================================================
    // SUMMARY
    // =================================================

    const data =
        Array.from(
            enterpriseMap.values()
        );


    const uniqueBeneficiaries =
        new Set();


    const uniquePrograms =
        new Set();


    const uniqueProjects =
        new Set();


    const uniqueActivities =
        new Set();


    let totalServiceDeliveries = 0;

    let totalQuantity = 0;

    let totalSupportValue = 0;


    data.forEach(
        enterprise => {

            enterprise.programs.forEach(
                program => {

                    uniquePrograms.add(
                        String(
                            program.program._id
                        )
                    );


                    program.beneficiaries.forEach(
                        beneficiary => {

                            uniqueBeneficiaries.add(
                                String(
                                    beneficiary
                                        .beneficiary
                                        ._id
                                )
                            );

                        }
                    );


                    program.projects.forEach(
                        project => {

                            uniqueProjects.add(
                                String(
                                    project.project._id
                                )
                            );


                            project.activities.forEach(
                                activity => {

                                    uniqueActivities.add(
                                        String(
                                            activity._id
                                        )
                                    );

                                }
                            );

                        }
                    );


                    totalServiceDeliveries +=
                        program.services.length;


                    totalQuantity +=
                        program.summary.quantity;


                    totalSupportValue =
                        roundMoney(totalSupportValue + program.summary.supportValue);

                }
            );

        }
    );


    return {

        reportName:
            "Enterprise Participation & Support Report",

        period: {

            type:
                filters.period || "all",

            year:
                filters.year || null,

            month:
                filters.month || null,

            quarter:
                filters.quarter || null,

            half:
                filters.half || null,

            startDate,

            endDate

        },

        summary: {

            totalEnterprises:
                enterprises.length,

            participatingEnterprises:
                data.filter(
                    enterprise =>
                        enterprise.programs.length > 0
                ).length,

            totalBeneficiaries:
                uniqueBeneficiaries.size,

            totalPrograms:
                uniquePrograms.size,

            totalProjects:
                uniqueProjects.size,

            totalActivities:
                uniqueActivities.size,

            totalServiceDeliveries,

            totalQuantity,

            totalSupportValue

        },

        data

    };

};


module.exports = {

    generate

};