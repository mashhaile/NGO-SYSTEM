const Beneficiary = require("../../models/Beneficiary");
const Enrollment = require("../../models/enrollment");
const EnterpriseMember = require("../../models/EnterpriseMember");
const ServiceDelivery = require("../../models/ServiceDelivery");
const ServiceDeliveryBeneficiary = require("../../models/ServiceDeliveryBeneficiary");
const {
    roundMoney,
    getBeneficiarySupportValue,
    buildDeliveryShares
} = require("./beneficiaryShares");

const {
    COUNTED_DELIVERY_FILTER
} = require("../../constants/serviceDeliveryStatus");

const {
    buildCommonFilters,
    buildDateFilter
} = require("./reportFilters");


// =====================================================
// EMPTY REPORT
// =====================================================

const buildEmptyReport = () => {

    return {

        title:
            "Beneficiary History Report",

        summary: {

            totalBeneficiaries:
                0,

            totalEnrollments:
                0,

            totalServices:
                0,

            totalSupportValue:
                0

        },

        statistics: {

            servicesByBeneficiary:
                [],

            supportByBeneficiary:
                [],

            enrollmentsByBeneficiary:
                [],

            servicesByProgram:
                []

        },

        charts: {

            servicesByBeneficiary:
                [],

            supportByBeneficiary:
                [],

            enrollmentsByBeneficiary:
                [],

            servicesByProgram:
                []

        },

        details:
            []

    };

};


// =====================================================
// BENEFICIARY HISTORY REPORT
// =====================================================

const generate = async (
    filters = {},
    context
) => {

    const {
        organizationId
    } = context;


    if (
        !organizationId
    ) {

        throw new Error(
            "Report organization context is required."
        );

    }


    // =================================================
    // BENEFICIARY QUERY
    // =================================================

    const beneficiaryQuery = {

        ...buildCommonFilters(
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

        )

    };


    if (
        filters.beneficiary
    ) {

        beneficiaryQuery._id =
            filters.beneficiary;

    }


    // =================================================
    // ENTERPRISE FILTER
    // =================================================

    if (
        filters.enterprise
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
            enterpriseBeneficiaryIds.length === 0
        ) {

            return buildEmptyReport();

        }


        beneficiaryQuery._id = {

            $in:
                enterpriseBeneficiaryIds

        };


        if (
            filters.beneficiary
        ) {

            beneficiaryQuery._id = {

                $in:
                    enterpriseBeneficiaryIds
                    .filter(
                        id =>
                            id.toString() ===
                            filters.beneficiary.toString()
                    )

            };


            if (
                beneficiaryQuery._id.$in.length === 0
            ) {

                return buildEmptyReport();

            }

        }

    }


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
        .sort({
            beneficiaryNumber: 1
        })
        .lean();


    if (
        beneficiaries.length === 0
    ) {

        return buildEmptyReport();

    }


    const report = [];


    // =================================================
    // FILTER STATE
    // =================================================

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


    const hasRelationshipFilter =
        hasProgramFilter ||
        hasProjectFilter ||
        hasActivityFilter ||
        hasActivityRunFilter ||
        hasEnterpriseFilter;


    const hasDateFilter =
        Boolean(
            filters.startDate ||
            filters.endDate ||
            filters.period
        );


    const hasHistoryFilter =
        hasRelationshipFilter ||
        hasDateFilter;


    // =================================================
    // BENEFICIARY HISTORY
    // =================================================

    for (
        const beneficiary
        of beneficiaries
    ) {

        // =============================================
        // ENROLLMENT HISTORY
        // =============================================

        const enrollmentQuery = {

            organization:
                organizationId,

            beneficiary:
                beneficiary._id,

            isDeleted:
                false

        };


        if (
            hasProgramFilter
        ) {

            enrollmentQuery.program =
                filters.program;

        }


        Object.assign(

            enrollmentQuery,

            buildDateFilter(

                filters,

                "enrollmentDate"

            )

        );


        const enrollments =
            await Enrollment.find(
                enrollmentQuery
            )
            .populate(
                "program",
                "name programCode status"
            )
            .sort({
                enrollmentDate: 1
            })
            .lean();


        // =============================================
        // BENEFICIARY SERVICE LINKS
        // =============================================

        const serviceLinks =
            await ServiceDeliveryBeneficiary.find({

                organization:
                    organizationId,

                beneficiary:
                    beneficiary._id

            })
            .sort({
                createdAt: 1
            })
            .lean();


        const serviceDeliveryIds =
            serviceLinks
                .map(
                    serviceLink =>
                        serviceLink.serviceDelivery
                )
                .filter(Boolean);


        // =============================================
        // SERVICE DELIVERY QUERY
        // =============================================

        let services = [];


        if (
            serviceDeliveryIds.length > 0
        ) {

            const serviceQuery = {

                organization:
                    organizationId,

                _id: {

                    $in:
                        serviceDeliveryIds

                },

                isDeleted:
                    false,
                ...COUNTED_DELIVERY_FILTER

            };


            if (
                hasProgramFilter
            ) {

                serviceQuery.program =
                    filters.program;

            }


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


            Object.assign(

                serviceQuery,

                buildDateFilter(

                    filters,

                    "deliveryDate"

                )

            );


            services =
                await ServiceDelivery.find(
                    serviceQuery
                )
                .populate(
                    "program",
                    "name programCode status"
                )
                .populate(
                    "project",
                    "name projectCode status"
                )
                .populate(
                    "activity",
                    "name activityCode activityType status"
                )
                .populate(
                    "activityRun",
                    "name runCode startDate endDate location status"
                )
                .populate(
                    {
                        path:
                            "items.serviceType",

                        select:
                            "value code"
                    }
                )
                .sort({
                    deliveryDate: 1
                })
                .lean();

        }


        // =============================================
        // SERVICE MAP
        // =============================================

        const serviceMap =
            new Map();


        for (
            const service
            of services
        ) {

            serviceMap.set(

                service._id.toString(),

                service

            );

        }


        // =============================================
        // SERVICE HISTORY
        // =============================================

        const serviceHistory = [];


        let totalSupportValue =
            0;


        // What everyone else on these deliveries was given
        const deliveryShares =
            await buildDeliveryShares(
                organizationId,
                serviceLinks.map(serviceLink => ({
                    ...serviceLink,
                    serviceDelivery: serviceMap.get(String(serviceLink.serviceDelivery))
                }))
            );


        for (
            const serviceLink
            of serviceLinks
        ) {

            const serviceId =
                serviceLink.serviceDelivery
                    ? serviceLink.serviceDelivery.toString()
                    : null;


            if (
                !serviceId
            ) {

                continue;

            }


            const service =
                serviceMap.get(
                    serviceId
                );


            if (
                !service
            ) {

                continue;

            }


            const serviceAmount =
                Number(
                    service.totalAmount || 0
                );


            // =========================================
            // BENEFICIARY SUPPORT VALUE
            // =========================================
            //
            // Individual service:
            // What this person received: their own
            // allocated value, or an equal share of
            // what the other allocations leave.
            //
            // Group service:
            // Community / Household / Institution
            // values belong to the delivery/group and
            // must not be duplicated for every linked
            // beneficiary.
            //
            // The service itself remains visible in the
            // beneficiary history in both cases.
            // =========================================

            const recipientType =
                service.recipientType ||
                "Individual";


            const beneficiarySupportValue =
                getBeneficiarySupportValue(
                    { ...serviceLink, serviceDelivery: service },
                    deliveryShares
                );


            totalSupportValue =
                roundMoney(totalSupportValue + beneficiarySupportValue);


            // =========================================
            // SERVICE TYPES
            // =========================================

            const serviceTypes = [];


            for (
                const item
                of service.items || []
            ) {

                if (
                    item.serviceType
                ) {

                    serviceTypes.push({

                        id:
                            item.serviceType._id,

                        name:
                            item.serviceType.value,

                        code:
                            item.serviceType.code

                    });

                }

            }


            // =========================================
            // SERVICE HISTORY RECORD
            // =========================================

            serviceHistory.push({

                serviceDeliveryId:
                    service._id,

                deliveryNumber:
                    service.deliveryNumber,

                recipientType,

                deliveryDate:
                    service.deliveryDate,

                deliveryLocation:
                    service.deliveryLocation,

                region:
                    service.region || null,

                zone:
                    service.zone || null,

                woreda:
                    service.woreda || null,

                status:
                    serviceLink.status,

                quantity:
                    serviceLink.quantity,

                remarks:
                    serviceLink.remarks,

                program:
                    service.program
                        ? {

                            id:
                                service.program._id,

                            name:
                                service.program.name,

                            programCode:
                                service.program.programCode,

                            status:
                                service.program.status

                        }
                        : null,

                project:
                    service.project
                        ? {

                            id:
                                service.project._id,

                            name:
                                service.project.name,

                            projectCode:
                                service.project.projectCode,

                            status:
                                service.project.status

                        }
                        : null,

                activity:
                    service.activity
                        ? {

                            id:
                                service.activity._id,

                            name:
                                service.activity.name,

                            activityCode:
                                service.activity.activityCode,

                            activityType:
                                service.activity.activityType,

                            status:
                                service.activity.status

                        }
                        : null,

                activityRun:
                    service.activityRun
                        ? {

                            id:
                                service.activityRun._id,

                            name:
                                service.activityRun.name,

                            runCode:
                                service.activityRun.runCode,

                            startDate:
                                service.activityRun.startDate,

                            endDate:
                                service.activityRun.endDate,

                            location:
                                service.activityRun.location,

                            status:
                                service.activityRun.status

                        }
                        : null,

                fundingSource:
                    service.fundingSource ||
                    null,

                donation:
                    service.donation ||
                    null,

                serviceTypes,

                totalAmount:
                    serviceAmount,

                beneficiarySupportValue:
                    beneficiarySupportValue

            });

        }


        // =============================================
        // PROGRAM HISTORY
        // =============================================

        const programMap =
            new Map();


        for (
            const enrollment
            of enrollments
        ) {

            if (
                !enrollment.program
            ) {

                continue;

            }


            const programId =
                enrollment.program._id.toString();


            if (
                !programMap.has(
                    programId
                )
            ) {

                programMap.set(

                    programId,

                    {

                        id:
                            enrollment.program._id,

                        name:
                            enrollment.program.name,

                        programCode:
                            enrollment.program.programCode,

                        status:
                            enrollment.program.status

                    }

                );

            }

        }


        for (
            const service
            of serviceHistory
        ) {

            if (
                !service.program
            ) {

                continue;

            }


            const programId =
                service.program.id.toString();


            if (
                !programMap.has(
                    programId
                )
            ) {

                programMap.set(

                    programId,

                    {

                        id:
                            service.program.id,

                        name:
                            service.program.name,

                        programCode:
                            service.program.programCode,

                        status:
                            service.program.status

                    }

                );

            }

        }


        const programs =
            Array.from(
                programMap.values()
            );


        // =============================================
        // HISTORY FILTER MATCHING
        // =============================================

        let historyMatches =
            true;


        if (
            hasHistoryFilter
        ) {

            historyMatches =
                false;


            // -----------------------------------------
            // PROGRAM
            // -----------------------------------------

            if (
                hasProgramFilter &&
                enrollments.length > 0
            ) {

                historyMatches =
                    true;

            }


            // -----------------------------------------
            // SERVICE HISTORY
            // -----------------------------------------

            const hasServiceSpecificFilter =
                hasProjectFilter ||
                hasActivityFilter ||
                hasActivityRunFilter;


            if (
                hasServiceSpecificFilter &&
                serviceHistory.length > 0
            ) {

                historyMatches =
                    true;

            }


            // -----------------------------------------
            // DATE-ONLY HISTORY
            // -----------------------------------------

            if (
                hasDateFilter &&
                !hasProgramFilter &&
                !hasServiceSpecificFilter
            ) {

                if (
                    enrollments.length > 0 ||
                    serviceHistory.length > 0
                ) {

                    historyMatches =
                        true;

                }

            }


            // -----------------------------------------
            // ENTERPRISE
            // -----------------------------------------

            if (
                hasEnterpriseFilter
            ) {

                historyMatches =
                    true;

            }

        }


        if (
            !historyMatches
        ) {

            continue;

        }


        // =============================================
        // BENEFICIARY REPORT DETAIL
        // =============================================

        report.push({

            beneficiaryId:
                beneficiary._id,

            beneficiaryNumber:
                beneficiary.beneficiaryNumber,

            beneficiary:
                [

                    beneficiary.firstName,

                    beneficiary.middleName,

                    beneficiary.lastName

                ]
                    .filter(Boolean)
                    .join(" "),

            gender:
                beneficiary.gender
                    ? {

                        id:
                            beneficiary.gender._id,

                        name:
                            beneficiary.gender.value,

                        code:
                            beneficiary.gender.code

                    }
                    : null,

            dateOfBirth:
                beneficiary.dateOfBirth,

            age:
                beneficiary.age,

            phone:
                beneficiary.phone,

            email:
                beneficiary.email,

            location: {

                country:
                    beneficiary.country,

                region:
                    beneficiary.region,

                zone:
                    beneficiary.zone,

                woreda:
                    beneficiary.woreda,

                kebele:
                    beneficiary.kebele,

                address:
                    beneficiary.address

            },

            educationLevel:
                beneficiary.educationLevel
                    ? {

                        id:
                            beneficiary.educationLevel._id,

                        name:
                            beneficiary.educationLevel.value,

                        code:
                            beneficiary.educationLevel.code

                    }
                    : null,

            occupation:
                beneficiary.occupation
                    ? {

                        id:
                            beneficiary.occupation._id,

                        name:
                            beneficiary.occupation.value,

                        code:
                            beneficiary.occupation.code

                    }
                    : null,

            maritalStatus:
                beneficiary.maritalStatus
                    ? {

                        id:
                            beneficiary.maritalStatus._id,

                        name:
                            beneficiary.maritalStatus.value,

                        code:
                            beneficiary.maritalStatus.code

                    }
                    : null,

            isPWD:
                beneficiary.isPWD,

            status:
                beneficiary.status,

            programs,

            enrollmentCount:
                enrollments.length,

            enrollmentHistory:
                enrollments.map(
                    enrollment => ({

                        enrollmentId:
                            enrollment._id,

                        enrollmentDate:
                            enrollment.enrollmentDate,

                        status:
                            enrollment.status,

                        completionDate:
                            enrollment.completionDate,

                        exitReason:
                            enrollment.exitReason,

                        program:
                            enrollment.program
                                ? {

                                    id:
                                        enrollment.program._id,

                                    name:
                                        enrollment.program.name,

                                    programCode:
                                        enrollment.program.programCode,

                                    status:
                                        enrollment.program.status

                                }
                                : null

                    })
                ),

            serviceHistory,

            totalServices:
                serviceHistory.length,

            totalSupportValue

        });

    }


    // =================================================
    // NO MATCHING HISTORY
    // =================================================

    if (
        report.length === 0
    ) {

        return buildEmptyReport();

    }


    // =================================================
    // SUMMARY
    // =================================================

    const totalBeneficiaries =
        report.length;


    const totalEnrollments =
        report.reduce(

            (
                sum,
                item
            ) =>
                sum +
                item.enrollmentCount,

            0

        );


    const totalServices =
        report.reduce(

            (
                sum,
                item
            ) =>
                sum +
                item.totalServices,

            0

        );


    // =================================================
    // BENEFICIARY-ATTRIBUTED SUPPORT
    // =================================================
    //
    // This value intentionally uses the beneficiary
    // support values calculated above.
    //
    // Group/community deliveries do not contribute
    // their totalAmount to each beneficiary.
    // =================================================

    const totalSupportValue =
        roundMoney(report.reduce(

            (
                sum,
                item
            ) =>
                sum +
                item.totalSupportValue,

            0

        ));


    // =================================================
    // STATISTICS
    // =================================================

    const servicesByBeneficiary =
        report.map(
            item => ({

                beneficiary:
                    `${item.beneficiaryNumber} - ${item.beneficiary}`,

                services:
                    item.totalServices

            })
        );


    const supportByBeneficiary =
        report.map(
            item => ({

                beneficiary:
                    `${item.beneficiaryNumber} - ${item.beneficiary}`,

                amount:
                    item.totalSupportValue

            })
        );


    const enrollmentsByBeneficiary =
        report.map(
            item => ({

                beneficiary:
                    `${item.beneficiaryNumber} - ${item.beneficiary}`,

                enrollments:
                    item.enrollmentCount

            })
        );


    // =================================================
    // SERVICES BY PROGRAM
    // =================================================
    //
    // This section represents actual service deliveries,
    // not beneficiary-attributed support.
    //
    // Therefore a community delivery linked to three
    // beneficiaries must be counted ONCE.
    // =================================================

    const servicesByProgramMap =
        new Map();


    const processedServiceIds =
        new Set();


    for (
        const beneficiary
        of report
    ) {

        for (
            const service
            of beneficiary.serviceHistory
        ) {

            if (
                !service.serviceDeliveryId
            ) {

                continue;

            }


            const serviceId =
                service.serviceDeliveryId.toString();


            if (
                processedServiceIds.has(
                    serviceId
                )
            ) {

                continue;

            }


            processedServiceIds.add(
                serviceId
            );


            const programName =
                service.program
                    ? service.program.name
                    : "Unassigned";


            const programCode =
                service.program
                    ? service.program.programCode
                    : null;


            const key =
                programCode
                    ? `${programCode} - ${programName}`
                    : programName;


            if (
                !servicesByProgramMap.has(
                    key
                )
            ) {

                servicesByProgramMap.set(

                    key,

                    {

                        program:
                            programName,

                        programCode:
                            programCode,

                        services:
                            0,

                        supportValue:
                            0

                    }

                );

            }


            const current =
                servicesByProgramMap.get(
                    key
                );


            current.services +=
                1;


            current.supportValue +=
                Number(
                    service.totalAmount || 0
                );

        }

    }


    const servicesByProgram =
        Array.from(
            servicesByProgramMap.values()
        );


    // =================================================
    // FINAL REPORT
    // =================================================

    return {

        title:
            "Beneficiary History Report",

        summary: {

            totalBeneficiaries,

            totalEnrollments,

            totalServices,

            totalSupportValue

        },

        statistics: {

            servicesByBeneficiary,

            supportByBeneficiary,

            enrollmentsByBeneficiary,

            servicesByProgram

        },

        charts: {

            servicesByBeneficiary,

            supportByBeneficiary,

            enrollmentsByBeneficiary,

            servicesByProgram

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