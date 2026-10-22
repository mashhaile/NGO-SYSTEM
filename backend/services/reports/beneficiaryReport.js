const Beneficiary = require("../../models/Beneficiary");
const Enrollment = require("../../models/enrollment");
const EnterpriseMember = require("../../models/EnterpriseMember");
const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildCommonFilters,
    buildPeriodFilter
} = require("./reportFilters");


// =====================================================
// HELPERS
// =====================================================

const toObjectIdString = (
    value
) => {

    if (!value) {

        return null;

    }

    return String(
        value
    );

};


const getLookupValue = (
    lookup
) => {

    if (!lookup) {

        return null;

    }


    if (
        typeof lookup === "string"
    ) {

        return lookup;

    }


    if (
        typeof lookup !== "object"
    ) {

        return String(
            lookup
        );

    }


    return (
        lookup.value ||
        lookup.label ||
        lookup.name ||
        lookup.displayName ||
        lookup.code ||
        lookup._doc?.value ||
        lookup._doc?.label ||
        lookup._doc?.name ||
        lookup._doc?.displayName ||
        lookup._doc?.code ||
        null
    );

};


const getLookupCode = (
    lookup
) => {

    if (!lookup) {

        return null;

    }


    if (
        typeof lookup !== "object"
    ) {

        return null;

    }


    return (
        lookup.code ||
        lookup._doc?.code ||
        null
    );

};


// =====================================================
// BENEFICIARY SUPPORT VALUE
// =====================================================

const getBeneficiarySupportValue = (
    service
) => {

    if (!service) {

        return 0;

    }


    const recipientType =
        service.recipientType ||
        "Individual";


    if (
        recipientType !== "Individual"
    ) {

        return 0;

    }


    return (
        Number(
            service.totalAmount
        ) || 0
    );

};


// =====================================================
// SERVICE ITEM NORMALIZATION
// =====================================================

const normalizeServiceItems = (
    service
) => {

    if (
        !service
    ) {

        return [];

    }


    if (
        !Array.isArray(
            service.items
        )
    ) {

        return [];

    }


    return service.items.map(
        item => {

            const serviceCategory =
                getLookupValue(
                    item.serviceCategory
                );


            const serviceCategoryCode =
                getLookupCode(
                    item.serviceCategory
                );


            const serviceType =
                getLookupValue(
                    item.serviceType
                );


            const serviceTypeCode =
                getLookupCode(
                    item.serviceType
                );


            const quantity =
                item.quantity !== undefined &&
                item.quantity !== null
                    ? Number(
                        item.quantity
                    )
                    : null;


            const unitCost =
                item.unitCost !== undefined &&
                item.unitCost !== null
                    ? Number(
                        item.unitCost
                    )
                    : null;


            const totalCost =
                item.totalCost !== undefined &&
                item.totalCost !== null
                    ? Number(
                        item.totalCost
                    )
                    : (
                        quantity !== null &&
                        unitCost !== null
                            ? quantity *
                              unitCost
                            : 0
                    );


            return {

                serviceCategory,

                serviceCategoryCode,

                serviceType,

                serviceTypeCode,

                quantity,

                unit:
                    item.unit ||
                    null,

                unitCost,

                totalCost,

                remarks:
                    item.remarks ||
                    null

            };

        }
    );

};


// =====================================================
// PROGRAM NORMALIZATION
// =====================================================

const normalizeProgram = (
    program
) => {

    if (
        !program
    ) {

        return null;

    }


    if (
        typeof program !== "object"
    ) {

        return {

            _id:
                null,

            name:
                String(
                    program
                ),

            programCode:
                null,

            category:
                null,

            description:
                null,

            targetBeneficiaries:
                null,

            startDate:
                null,

            endDate:
                null,

            status:
                null

        };

    }


    return {

        _id:
            program._id ||
            null,

        name:
            program.name ||
            null,

        programCode:
            program.programCode ||
            null,

        category:
            program.category ||
            null,

        description:
            program.description ||
            null,

        targetBeneficiaries:
            program.targetBeneficiaries !== undefined
                ? program.targetBeneficiaries
                : null,

        startDate:
            program.startDate ||
            null,

        endDate:
            program.endDate ||
            null,

        status:
            program.status ||
            null

    };

};


// =====================================================
// PROJECT NORMALIZATION
// =====================================================

const normalizeProject = (
    project
) => {

    if (
        !project
    ) {

        return null;

    }


    if (
        typeof project !== "object"
    ) {

        return {

            _id:
                null,

            name:
                String(
                    project
                ),

            projectCode:
                null,

            description:
                null,

            startDate:
                null,

            endDate:
                null,

            status:
                null,

            program:
                null

        };

    }


    return {

        _id:
            project._id ||
            null,

        name:
            project.name ||
            null,

        projectCode:
            project.projectCode ||
            null,

        description:
            project.description ||
            null,

        startDate:
            project.startDate ||
            null,

        endDate:
            project.endDate ||
            null,

        status:
            project.status ||
            null,

        program:
            normalizeProgram(
                project.program
            )

    };

};


// =====================================================
// ACTIVITY NORMALIZATION
// =====================================================

const normalizeActivity = (
    activity
) => {

    if (
        !activity
    ) {

        return null;

    }


    if (
        typeof activity !== "object"
    ) {

        return {

            _id:
                null,

            name:
                String(
                    activity
                ),

            activityCode:
                null,

            activityType:
                null,

            participantSource:
                null,

            targetGroups:
                [],

            description:
                null,

            activityDate:
                null,

            location:
                null,

            facilitator:
                null,

            targetParticipants:
                null,

            status:
                null,

            remarks:
                null,

            project:
                null,

            program:
                null

        };

    }


    return {

        _id:
            activity._id ||
            null,

        name:
            activity.name ||
            null,

        activityCode:
            activity.activityCode ||
            null,

        activityType:
            activity.activityType ||
            null,

        participantSource:
            activity.participantSource ||
            null,

        targetGroups:
            Array.isArray(
                activity.targetGroups
            )
                ? activity.targetGroups
                : [],

        description:
            activity.description ||
            null,

        activityDate:
            activity.activityDate ||
            null,

        location:
            activity.location ||
            null,

        facilitator:
            activity.facilitator ||
            null,

        targetParticipants:
            activity.targetParticipants !== undefined
                ? activity.targetParticipants
                : null,

        status:
            activity.status ||
            null,

        remarks:
            activity.remarks ||
            null,

        project:
            normalizeProject(
                activity.project
            ),

        program:
            normalizeProgram(
                activity.program
            )

    };

};


// =====================================================
// ACTIVITY RUN NORMALIZATION
// =====================================================

const normalizeActivityRun = (
    activityRun
) => {

    if (
        !activityRun
    ) {

        return null;

    }


    if (
        typeof activityRun !== "object"
    ) {

        return {

            _id:
                null,

            name:
                String(
                    activityRun
                ),

            runCode:
                null,

            startDate:
                null,

            endDate:
                null,

            location:
                null,

            status:
                null,

            targetGroup:
                null,

            notes:
                null,

            activity:
                null,

            project:
                null,

            program:
                null

        };

    }


    return {

        _id:
            activityRun._id ||
            null,

        name:
            activityRun.name ||
            null,

        runCode:
            activityRun.runCode ||
            null,

        startDate:
            activityRun.startDate ||
            null,

        endDate:
            activityRun.endDate ||
            null,

        location:
            activityRun.location ||
            null,

        status:
            activityRun.status ||
            null,

        targetGroup:
            activityRun.targetGroup ||
            null,

        notes:
            activityRun.notes ||
            null,

        activity:
            normalizeActivity(
                activityRun.activity
            ),

        project:
            normalizeProject(
                activityRun.project
            ),

        program:
            normalizeProgram(
                activityRun.program
            )

    };

};


// =====================================================
// EMPTY REPORT
// =====================================================

const buildEmptyReport = () => {

    return {

        title:
            "Beneficiary Report",

        summary: {

            totalBeneficiaries:
                0,

            totalServicesReceived:
                0,

            totalSupportValue:
                0

        },

        statistics: {

            beneficiariesByGender:
                [],

            beneficiariesByStatus:
                [],

            beneficiariesByProgram:
                [],

            servicesByBeneficiary:
                [],

            supportValueByBeneficiary:
                []

        },

        charts: {

            beneficiariesByGender:
                [],

            beneficiariesByStatus:
                [],

            beneficiariesByProgram:
                [],

            servicesByBeneficiary:
                [],

            supportValueByBeneficiary:
                []

        },

        details:
            []

    };

};


// =====================================================
// BUILD MATCHING BENEFICIARY IDS
// =====================================================

const getMatchingBeneficiaryIds = async (
    filters = {},
    organizationId
) => {

    const hasProgramFilter =
        Boolean(
            filters.program
        );

    const hasProjectFilter =
        Boolean(
            filters.project
        );

    const hasActivityFilter =
        Boolean(
            filters.activity
        );

    const hasActivityRunFilter =
        Boolean(
            filters.activityRun
        );

    const hasEnterpriseFilter =
        Boolean(
            filters.enterprise
        );


    if (
        !hasProgramFilter &&
        !hasProjectFilter &&
        !hasActivityFilter &&
        !hasActivityRunFilter &&
        !hasEnterpriseFilter
    ) {

        return null;

    }


    let matchingIds =
        null;


    // =================================================
    // PROGRAM FILTER
    // =================================================

    if (
        hasProgramFilter
    ) {

        const enrollmentRows =
            await Enrollment.find({

                organization:
                    organizationId,

                program:
                    filters.program,

                isDeleted:
                    false

            })
            .select(
                "beneficiary"
            )
            .lean();


        const programBeneficiaryIds =
            enrollmentRows
                .map(
                    row =>
                        row.beneficiary
                )
                .filter(Boolean);


        matchingIds =
            programBeneficiaryIds;

    }


    // =================================================
    // SERVICE-BASED FILTERS
    // =================================================

    if (
        hasProjectFilter ||
        hasActivityFilter ||
        hasActivityRunFilter
    ) {

        const serviceQuery = {

            organization:
                organizationId,

            isDeleted:
                false,
            ...COUNTED_DELIVERY_FILTER

        };


        if (
            hasProjectFilter
        ) {

            serviceQuery.project =
                filters.project;

        }


        if (
            hasActivityFilter
        ) {

            serviceQuery.activity =
                filters.activity;

        }


        if (
            hasActivityRunFilter
        ) {

            serviceQuery.activityRun =
                filters.activityRun;

        }


        const services =
            await ServiceDelivery.find(
                serviceQuery
            )
            .select(
                "_id"
            )
            .lean();


        const serviceIds =
            services.map(
                service =>
                    service._id
            );


        if (
            serviceIds.length === 0
        ) {

            return [];

        }


        const serviceLinks =
            await ServiceDeliveryBeneficiary.find({

                organization:
                    organizationId,

                serviceDelivery: {

                    $in:
                        serviceIds

                }

            })
            .select(
                "beneficiary"
            )
            .lean();


        const serviceBeneficiaryIds =
            serviceLinks
                .map(
                    link =>
                        link.beneficiary
                )
                .filter(Boolean);


        if (
            matchingIds === null
        ) {

            matchingIds =
                serviceBeneficiaryIds;

        } else {

            const serviceIdSet =
                new Set(
                    serviceBeneficiaryIds.map(
                        id =>
                            toObjectIdString(
                                id
                            )
                    )
                );


            matchingIds =
                matchingIds.filter(
                    id =>
                        serviceIdSet.has(
                            toObjectIdString(
                                id
                            )
                        )
                );

        }

    }


    // =================================================
    // ENTERPRISE FILTER
    // =================================================

    if (
        hasEnterpriseFilter
    ) {

        const enterpriseMembers =
            await EnterpriseMember.find({

                organization:
                    organizationId,

                enterprise:
                    filters.enterprise,

                isDeleted:
                    false

            })
            .select(
                "beneficiary"
            )
            .lean();


        const enterpriseBeneficiaryIds =
            enterpriseMembers
                .map(
                    member =>
                        member.beneficiary
                )
                .filter(Boolean);


        if (
            matchingIds === null
        ) {

            matchingIds =
                enterpriseBeneficiaryIds;

        } else {

            const enterpriseIdSet =
                new Set(
                    enterpriseBeneficiaryIds.map(
                        id =>
                            toObjectIdString(
                                id
                            )
                    )
                );


            matchingIds =
                matchingIds.filter(
                    id =>
                        enterpriseIdSet.has(
                            toObjectIdString(
                                id
                            )
                        )
                );

        }

    }


    return matchingIds || [];

};


// =====================================================
// BENEFICIARY REPORT
// =====================================================

const generate = async (
    filters = {},
    context
) => {

    const {
        organizationId
    } = context;


    if (!organizationId) {

        throw new Error(
            "Report organization context is required."
        );

    }


    // =================================================
    // BENEFICIARY FILTERS
    // =================================================

    const beneficiaryQuery =
        buildCommonFilters(

            filters,

            context,

            {

                allowedFields: [

                    "beneficiary",

                    "gender",

                    "status",

                    "createdBy"

                ]

            }

        );


    // =================================================
    // RELATIONSHIP FILTERS
    // =================================================

    const matchingBeneficiaryIds =
        await getMatchingBeneficiaryIds(
            filters,
            organizationId
        );


    if (
        matchingBeneficiaryIds !== null
    ) {

        if (
            matchingBeneficiaryIds.length === 0
        ) {

            return buildEmptyReport();

        }


        beneficiaryQuery._id = {

            $in:
                matchingBeneficiaryIds

        };

    }


    // =================================================
    // DATE / PERIOD FILTER
    // =================================================

    const periodFilter =
        buildPeriodFilter(

            filters,

            "createdAt"

        );


    Object.assign(

        beneficiaryQuery,

        periodFilter

    );


    // =================================================
    // LOAD BENEFICIARIES
    // =================================================

    const beneficiaries =
        await Beneficiary.find(
            beneficiaryQuery
        )
        .populate(
            "gender",
            "value code"
        )
        .populate(
            "educationLevel",
            "value code"
        )
        .populate(
            "occupation",
            "value code"
        )
        .populate(
            "maritalStatus",
            "value code"
        )
        .populate(
            "disabilityType",
            "value code"
        )
        .populate(
            "vulnerableGroups",
            "value code"
        )
        .lean();


    if (
        beneficiaries.length === 0
    ) {

        return buildEmptyReport();

    }


    // =================================================
    // BENEFICIARY IDS
    // =================================================

    const beneficiaryIds =
        beneficiaries.map(
            beneficiary =>
                beneficiary._id
        );


    // =================================================
    // LOAD ENROLLMENTS
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


    if (
        filters.program
    ) {

        enrollmentQuery.program =
            filters.program;

    }


    const enrollments =
        await Enrollment.find(
            enrollmentQuery
        )
        .populate({

            path:
                "program",

            select:
                "name programCode category description targetBeneficiaries startDate endDate status"

        })
        .lean();


    // =================================================
    // LOAD SERVICE DELIVERY RELATIONSHIPS
    // =================================================

    const serviceLinkQuery = {

        organization:
            organizationId,

        beneficiary: {

            $in:
                beneficiaryIds

        }

    };


    const serviceDeliveryLinks =
        await ServiceDeliveryBeneficiary.find(
            serviceLinkQuery
        )
        .populate({

            path:
                "serviceDelivery",

            match: {

                organization:
                    organizationId,

                isDeleted:
                    false,
                ...COUNTED_DELIVERY_FILTER

            },

            select:
                "deliveryNumber recipientType program project activity activityRun fundingSource donation items totalAmount deliveryDate region zone woreda deliveryLocation status",

            populate: [

                // =========================================
                // PROGRAM
                // =========================================

                {

                    path:
                        "program",

                    select:
                        "name programCode category description targetBeneficiaries startDate endDate status"

                },

                // =========================================
                // PROJECT
                // =========================================

                {

                    path:
                        "project",

                    select:
                        "name projectCode description donor projectManager startDate endDate status",

                    populate: [

                        {

                            path:
                                "program",

                            select:
                                "name programCode category description targetBeneficiaries startDate endDate status"

                        }

                    ]

                },

                // =========================================
                // ACTIVITY
                // =========================================

                {

                    path:
                        "activity",

                    select:
                        "name activityCode activityType participantSource targetGroups description activityDate location facilitator targetParticipants status remarks project",

                    populate: [

                        {

                            path:
                                "project",

                            select:
                                "name projectCode description donor projectManager startDate endDate status",

                            populate: [

                                {

                                    path:
                                        "program",

                                    select:
                                        "name programCode category description targetBeneficiaries startDate endDate status"

                                }

                            ]

                        }

                    ]

                },

                // =========================================
                // ACTIVITY RUN
                // =========================================

                {

                    path:
                        "activityRun",

                    select:
                        "name runCode startDate endDate location trainer targetGroup status notes activity project program",

                    populate: [

                        {

                            path:
                                "activity",

                            select:
                                "name activityCode activityType participantSource targetGroups description activityDate location facilitator targetParticipants status remarks"

                        },

                        {

                            path:
                                "project",

                            select:
                                "name projectCode description donor projectManager startDate endDate status",

                            populate: [

                                {

                                    path:
                                        "program",

                                    select:
                                        "name programCode category description targetBeneficiaries startDate endDate status"

                                }

                            ]

                        },

                        {

                            path:
                                "program",

                            select:
                                "name programCode category description targetBeneficiaries startDate endDate status"

                        }

                    ]

                },

                // =========================================
                // FUNDING SOURCE
                // =========================================

                {

                    path:
                        "fundingSource",

                    select:
                        "value label name displayName code"

                },

                // =========================================
                // SERVICE CATEGORY
                // =========================================

                {

                    path:
                        "items.serviceCategory",

                    select:
                        "value label name displayName code"

                },

                // =========================================
                // SERVICE TYPE
                // =========================================

                {

                    path:
                        "items.serviceType",

                    select:
                        "value label name displayName code"

                }

            ]

        })
        .lean();


    // =================================================
    // FILTER SERVICE RELATIONSHIPS
    // =================================================

    const validServiceLinks =
        serviceDeliveryLinks.filter(

            link => {

                const service =
                    link.serviceDelivery;


                if (
                    !service
                ) {

                    return false;

                }


                if (
                    filters.program &&
                    String(
                        service.program?._id
                    ) !== String(
                        filters.program
                    )
                ) {

                    return false;

                }


                if (
                    filters.project &&
                    String(
                        service.project?._id
                    ) !== String(
                        filters.project
                    )
                ) {

                    return false;

                }


                if (
                    filters.activity &&
                    String(
                        service.activity?._id
                    ) !== String(
                        filters.activity
                    )
                ) {

                    return false;

                }


                if (
                    filters.activityRun &&
                    String(
                        service.activityRun?._id
                    ) !== String(
                        filters.activityRun
                    )
                ) {

                    return false;

                }


                return true;

            }

        );


    // =================================================
    // LOAD ENTERPRISE MEMBERS
    // =================================================

    const enterpriseQuery = {

        organization:
            organizationId,

        beneficiary: {

            $in:
                beneficiaryIds

        },

        isDeleted:
            false

    };


    if (
        filters.enterprise
    ) {

        enterpriseQuery.enterprise =
            filters.enterprise;

    }


    const enterpriseMembers =
        await EnterpriseMember.find(
            enterpriseQuery
        )
        .populate(
            "enterprise"
        )
        .lean();


    // =================================================
    // ENROLLMENT MAP
    // =================================================

    const enrollmentMap =
        new Map();


    enrollments.forEach(
        enrollment => {

            const beneficiaryId =
                toObjectIdString(
                    enrollment.beneficiary
                );


            if (
                !enrollmentMap.has(
                    beneficiaryId
                )
            ) {

                enrollmentMap.set(

                    beneficiaryId,

                    []

                );

            }


            enrollmentMap
                .get(
                    beneficiaryId
                )
                .push(
                    enrollment
                );

        }
    );


    // =================================================
    // SERVICE MAP
    // =================================================

    const serviceMap =
        new Map();


    validServiceLinks.forEach(
        link => {

            const beneficiaryId =
                toObjectIdString(
                    link.beneficiary
                );


            if (
                !serviceMap.has(
                    beneficiaryId
                )
            ) {

                serviceMap.set(

                    beneficiaryId,

                    []

                );

            }


            serviceMap
                .get(
                    beneficiaryId
                )
                .push(
                    link
                );

        }
    );


    // =================================================
    // ENTERPRISE MAP
    // =================================================

    const enterpriseMap =
        new Map();


    enterpriseMembers.forEach(
        member => {

            const beneficiaryId =
                toObjectIdString(
                    member.beneficiary
                );


            if (
                !enterpriseMap.has(
                    beneficiaryId
                )
            ) {

                enterpriseMap.set(

                    beneficiaryId,

                    []

                );

            }


            enterpriseMap
                .get(
                    beneficiaryId
                )
                .push(
                    member
                );

        }
    );


    // =================================================
    // BUILD REPORT
    // =================================================

    const report = [];


    for (
        const beneficiary
        of beneficiaries
    ) {

        const beneficiaryId =
            toObjectIdString(
                beneficiary._id
            );


        const beneficiaryEnrollments =
            enrollmentMap.get(
                beneficiaryId
            ) || [];


        const beneficiaryServices =
            serviceMap.get(
                beneficiaryId
            ) || [];


        const beneficiaryEnterprises =
            enterpriseMap.get(
                beneficiaryId
            ) || [];


        const totalSupportValue =
            beneficiaryServices.reduce(

                (
                    sum,
                    link
                ) => {

                    const service =
                        link.serviceDelivery;


                    const beneficiarySupportValue =
                        getBeneficiarySupportValue(
                            service
                        );


                    return (
                        sum +
                        beneficiarySupportValue
                    );

                },

                0

            );


        const fullName = [

            beneficiary.firstName,

            beneficiary.middleName,

            beneficiary.lastName

        ]
        .filter(
            value =>
                value
        )
        .join(" ");


        const beneficiaryDisplayName =
            beneficiary.beneficiaryNumber
                ? `${beneficiary.beneficiaryNumber} - ${fullName}`
                : fullName;


        report.push({

            beneficiaryId:
                beneficiary._id,

            beneficiaryNumber:
                beneficiary.beneficiaryNumber,

            beneficiary:
                fullName,

            beneficiaryDisplayName,

            firstName:
                beneficiary.firstName,

            middleName:
                beneficiary.middleName,

            lastName:
                beneficiary.lastName,

            gender:
                beneficiary.gender?.value ||
                null,

            genderCode:
                beneficiary.gender?.code ||
                null,

            dateOfBirth:
                beneficiary.dateOfBirth ||
                null,

            age:
                beneficiary.age,

            educationLevel:
                beneficiary.educationLevel?.value ||
                null,

            occupation:
                beneficiary.occupation?.value ||
                null,

            maritalStatus:
                beneficiary.maritalStatus?.value ||
                null,

            isPWD:
                beneficiary.isPWD,

            disabilityType:
                beneficiary.disabilityType?.value ||
                null,

            vulnerableGroups:
                Array.isArray(
                    beneficiary.vulnerableGroups
                )
                    ? beneficiary.vulnerableGroups
                        .map(
                            lookup =>
                                lookup?.value
                        )
                        .filter(
                            value =>
                                value
                        )
                    : [],

            status:
                beneficiary.status,

            country:
                beneficiary.country ||
                null,

            region:
                beneficiary.region ||
                null,

            zone:
                beneficiary.zone ||
                null,

            woreda:
                beneficiary.woreda ||
                null,

            kebele:
                beneficiary.kebele ||
                null,

            address:
                beneficiary.address ||
                null,

            enterprises:
                beneficiaryEnterprises.map(

                    member => ({

                        enterpriseId:
                            member.enterprise?._id ||
                            null,

                        enterprise:
                            member.enterprise?.name ||
                            null,

                        enterpriseNumber:
                            member.enterprise?.enterpriseNumber ||
                            null,

                        memberRole:
                            member.memberRole,

                        joinedDate:
                            member.joinedDate,

                        leftDate:
                            member.leftDate,

                        status:
                            member.status

                    })

                ),

            // =================================================
            // PROGRAM NAMES
            // =================================================

            programs:
                beneficiaryEnrollments
                    .map(
                        enrollment =>
                            enrollment.program?.name
                    )
                    .filter(
                        program =>
                            program
                    ),

            // =================================================
            // COMPLETE ENROLLMENT DATA
            // =================================================

            enrollments:
                beneficiaryEnrollments.map(

                    enrollment => {

                        const program =
                            normalizeProgram(
                                enrollment.program
                            );


                        return {

                            enrollmentId:
                                enrollment._id,

                            programId:
                                program?._id ||
                                null,

                            program,

                            programName:
                                program?.name ||
                                null,

                            programCode:
                                program?.programCode ||
                                null,

                            enrollmentDate:
                                enrollment.enrollmentDate,

                            status:
                                enrollment.status,

                            completionDate:
                                enrollment.completionDate,

                            exitReason:
                                enrollment.exitReason,

                            remarks:
                                enrollment.remarks ||
                                null

                        };

                    }

                ),

            servicesReceived:
                beneficiaryServices.length,

            totalValue:
                totalSupportValue,

            // =================================================
            // COMPLETE SERVICE DATA
            // =================================================

            services:
                beneficiaryServices.map(

                    link => {

                        const service =
                            link.serviceDelivery;


                        const directProgram =
                            normalizeProgram(
                                service?.program
                            );


                        const directProject =
                            normalizeProject(
                                service?.project
                            );


                        const directActivity =
                            normalizeActivity(
                                service?.activity
                            );


                        const directActivityRun =
                            normalizeActivityRun(
                                service?.activityRun
                            );


                        // =========================================
                        // HIERARCHY FALLBACKS
                        // =========================================

                        const hierarchyProgram =
                            directProgram ||
                            directActivityRun?.program ||
                            directActivity?.program ||
                            directProject?.program ||
                            null;


                        const hierarchyProject =
                            directProject ||
                            directActivityRun?.project ||
                            directActivity?.project ||
                            null;


                        const hierarchyActivity =
                            directActivity ||
                            directActivityRun?.activity ||
                            null;


                        const hierarchyActivityRun =
                            directActivityRun ||
                            null;


                        const serviceTotalAmount =
                            Number(
                                service?.totalAmount
                            ) || 0;


                        const recipientType =
                            service?.recipientType ||
                            "Individual";


                        const beneficiarySupportValue =
                            getBeneficiarySupportValue(
                                service
                            );


                        const serviceItems =
                            normalizeServiceItems(
                                service
                            );


                        const serviceTypes =
                            [
                                ...new Map(
                                    serviceItems
                                        .filter(
                                            item =>
                                                item.serviceType
                                        )
                                        .map(
                                            item => [
                                                item.serviceTypeCode ||
                                                item.serviceType,
                                                item.serviceType
                                            ]
                                        )
                                ).values()
                            ];


                        const serviceCategories =
                            [
                                ...new Map(
                                    serviceItems
                                        .filter(
                                            item =>
                                                item.serviceCategory
                                        )
                                        .map(
                                            item => [
                                                item.serviceCategoryCode ||
                                                item.serviceCategory,
                                                item.serviceCategory
                                            ]
                                        )
                                ).values()
                            ];


                        return {

                            serviceDeliveryId:
                                service?._id ||
                                null,

                            deliveryNumber:
                                service?.deliveryNumber ||
                                null,

                            deliveryDate:
                                service?.deliveryDate ||
                                null,

                            recipientType,

                            // =====================================
                            // COMPLETE PROGRAM OBJECT
                            // =====================================

                            program:
                                hierarchyProgram,

                            programId:
                                hierarchyProgram?._id ||
                                null,

                            programName:
                                hierarchyProgram?.name ||
                                null,

                            programCode:
                                hierarchyProgram?.programCode ||
                                null,

                            // =====================================
                            // COMPLETE PROJECT OBJECT
                            // =====================================

                            project:
                                hierarchyProject,

                            projectId:
                                hierarchyProject?._id ||
                                null,

                            projectName:
                                hierarchyProject?.name ||
                                null,

                            projectCode:
                                hierarchyProject?.projectCode ||
                                null,

                            // =====================================
                            // COMPLETE ACTIVITY OBJECT
                            // =====================================

                            activity:
                                hierarchyActivity,

                            activityId:
                                hierarchyActivity?._id ||
                                null,

                            activityName:
                                hierarchyActivity?.name ||
                                null,

                            activityCode:
                                hierarchyActivity?.activityCode ||
                                null,

                            activityType:
                                hierarchyActivity?.activityType ||
                                null,

                            // =====================================
                            // COMPLETE ACTIVITY RUN OBJECT
                            // =====================================

                            activityRun:
                                hierarchyActivityRun,

                            activityRunId:
                                hierarchyActivityRun?._id ||
                                null,

                            activityRunName:
                                hierarchyActivityRun?.name ||
                                null,

                            runCode:
                                hierarchyActivityRun?.runCode ||
                                null,

                            activityRunStartDate:
                                hierarchyActivityRun?.startDate ||
                                null,

                            activityRunEndDate:
                                hierarchyActivityRun?.endDate ||
                                null,

                            activityRunLocation:
                                hierarchyActivityRun?.location ||
                                null,

                            // =====================================
                            // FUNDING
                            // =====================================

                            fundingSource:
                                getLookupValue(
                                    service?.fundingSource
                                ),

                            fundingSourceCode:
                                getLookupCode(
                                    service?.fundingSource
                                ),

                            donation:
                                service?.donation ||
                                null,

                            // =====================================
                            // DELIVERY
                            // =====================================

                            deliveryLocation:
                                service?.deliveryLocation ||
                                null,

                            region:
                                service?.region ||
                                null,

                            zone:
                                service?.zone ||
                                null,

                            woreda:
                                service?.woreda ||
                                null,

                            status:
                                service?.status ||
                                null,

                            beneficiaryStatus:
                                link.status ||
                                null,

                            // =====================================
                            // SERVICE ITEMS
                            // =====================================

                            serviceCategories,

                            serviceTypes,

                            items:
                                serviceItems,

                            quantity:
                                serviceItems.length === 1
                                    ? serviceItems[0].quantity
                                    : null,

                            unit:
                                serviceItems.length === 1
                                    ? serviceItems[0].unit
                                    : null,

                            unitCost:
                                serviceItems.length === 1
                                    ? serviceItems[0].unitCost
                                    : null,

                            remarks:
                                serviceItems.length === 1
                                    ? serviceItems[0].remarks
                                    : null,

                            totalAmount:
                                serviceTotalAmount,

                            beneficiarySupportValue

                        };

                    }

                )

        });

    }


    // =====================================================
    // SUMMARY
    // =====================================================

    const totalServicesReceived =
        report.reduce(

            (
                sum,
                item
            ) =>
                sum +
                item.servicesReceived,

            0

        );


    const totalSupportValue =
        report.reduce(

            (
                sum,
                item
            ) =>
                sum +
                item.totalValue,

            0

        );


    // =====================================================
    // GENDER STATISTICS
    // =====================================================

    const genderCounts =
        new Map();


    report.forEach(
        item => {

            const gender =
                item.gender ||
                "Unknown";


            genderCounts.set(

                gender,

                (
                    genderCounts.get(
                        gender
                    ) || 0
                ) + 1

            );

        }
    );


    const beneficiariesByGender =
        Array.from(
            genderCounts.entries()
        )
        .map(
            ([gender, count]) => ({

                gender,

                count

            })
        );


    // =====================================================
    // STATUS STATISTICS
    // =====================================================

    const statusCounts =
        new Map();


    report.forEach(
        item => {

            const status =
                item.status ||
                "Unknown";


            statusCounts.set(

                status,

                (
                    statusCounts.get(
                        status
                    ) || 0
                ) + 1

            );

        }
    );


    const beneficiariesByStatus =
        Array.from(
            statusCounts.entries()
        )
        .map(
            ([status, count]) => ({

                status,

                count

            })
        );


    // =====================================================
    // PROGRAM STATISTICS
    // =====================================================

    const programCounts =
        new Map();


    report.forEach(
        item => {

            item.enrollments.forEach(
                enrollment => {

                    const programName =
                        enrollment.program?.name ||
                        enrollment.programName ||
                        enrollment.program ||
                        "Unknown";


                    const programCode =
                        enrollment.program?.programCode ||
                        enrollment.programCode ||
                        null;


                    const programLabel =
                        programCode
                            ? `${programCode} - ${programName}`
                            : programName;


                    if (
                        !programCounts.has(
                            programLabel
                        )
                    ) {

                        programCounts.set(

                            programLabel,

                            {

                                program:
                                    programName,

                                programCode,

                                count:
                                    0

                            }

                        );

                    }


                    const current =
                        programCounts.get(
                            programLabel
                        );


                    current.count += 1;

                }
            );

        }
    );


    const beneficiariesByProgram =
        Array.from(
            programCounts.values()
        );


    // =====================================================
    // SERVICE CHART DATA
    // =====================================================

    const servicesByBeneficiary =
        report.map(
            item => ({

                beneficiary:
                    item.beneficiaryDisplayName,

                services:
                    item.servicesReceived

            })
        );


    // =====================================================
    // SUPPORT VALUE CHART DATA
    // =====================================================

    const supportValueByBeneficiary =
        report.map(
            item => ({

                beneficiary:
                    item.beneficiaryDisplayName,

                amount:
                    item.totalValue

            })
        );


    // =====================================================
    // RETURN REPORT
    // =====================================================

    return {

        title:
            "Beneficiary Report",

        summary: {

            totalBeneficiaries:
                report.length,

            totalServicesReceived,

            totalSupportValue

        },

        statistics: {

            beneficiariesByGender,

            beneficiariesByStatus,

            beneficiariesByProgram,

            servicesByBeneficiary,

            supportValueByBeneficiary

        },

        charts: {

            beneficiariesByGender,

            beneficiariesByStatus,

            beneficiariesByProgram,

            servicesByBeneficiary,

            supportValueByBeneficiary

        },

        details:
            report

    };

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    generate

};