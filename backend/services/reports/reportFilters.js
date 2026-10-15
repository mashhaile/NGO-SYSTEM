// =====================================================
// COMMON REPORT FILTERS
// =====================================================
//
// This module contains filters that can safely be shared
// across report modules.
//
// IMPORTANT:
// Do NOT place model-specific relationship filters here.
//
// Examples:
// - enterprise -> EnterpriseMember relationship
// - program -> Enrollment / ServiceDelivery relationship
// - project -> ServiceDelivery relationship
// - activity -> ServiceDelivery relationship
//
// Those relationships must be handled by the individual
// report because different report models use different
// relationship paths.
//
// =====================================================


// =====================================================
// VALIDATE FILTER VALUE
// =====================================================

const hasValue = (
    value
) => {

    return (
        value !== undefined &&
        value !== null &&
        value !== ""
    );

};


// =====================================================
// PARSE REPORT DATE
// =====================================================
//
// Report dates are calendar dates in:
//
// YYYY-MM-DD
//
// They are intentionally parsed using numeric
// components instead of:
//
// new Date("YYYY-MM-DD")
//
// This prevents UTC/local-time conversion from shifting
// the reporting date.
//
// =====================================================

const parseReportDate = (
    value
) => {

    if (
        !hasValue(
            value
        )
    ) {

        return null;

    }


    if (
        value instanceof Date
    ) {

        if (
            Number.isNaN(
                value.getTime()
            )
        ) {

            return null;

        }


        return new Date(
            value.getTime()
        );

    }


    const stringValue =
        String(
            value
        ).trim();


    const match =
        stringValue.match(
            /^(\d{4})-(\d{2})-(\d{2})$/
        );


    if (
        !match
    ) {

        return null;

    }


    const year =
        Number(
            match[1]
        );

    const month =
        Number(
            match[2]
        );

    const day =
        Number(
            match[3]
        );


    if (
        !Number.isInteger(
            year
        ) ||
        !Number.isInteger(
            month
        ) ||
        !Number.isInteger(
            day
        )
    ) {

        return null;

    }


    if (
        month < 1 ||
        month > 12
    ) {

        return null;

    }


    if (
        day < 1 ||
        day >
        new Date(
            year,
            month,
            0
        ).getDate()
    ) {

        return null;

    }


    return new Date(
        year,
        month - 1,
        day,
        0,
        0,
        0,
        0
    );

};


// =====================================================
// BUILD COMMON REPORT FILTERS
// =====================================================

const buildCommonFilters = (
    filters = {},
    context = null,
    options = {}
) => {

    const query = {};

    const allowedFields =
        Array.isArray(
            options.allowedFields
        )
            ? options.allowedFields
            : [];


    // =================================================
    // ORGANIZATION ISOLATION
    // =================================================

    if (
        context?.organizationId
    ) {

        query.organization =
            context.organizationId;

    }


    // =================================================
    // MODEL-SPECIFIC COMMON FIELDS
    // =================================================

    if (
        allowedFields.includes(
            "beneficiary"
        ) &&
        hasValue(
            filters.beneficiary
        )
    ) {

        query.beneficiary =
            filters.beneficiary;

    }


    if (
        allowedFields.includes(
            "enrollment"
        ) &&
        hasValue(
            filters.enrollment
        )
    ) {

        query.enrollment =
            filters.enrollment;

    }


    if (
        allowedFields.includes(
            "program"
        ) &&
        hasValue(
            filters.program
        )
    ) {

        query.program =
            filters.program;

    }


    if (
        allowedFields.includes(
            "project"
        ) &&
        hasValue(
            filters.project
        )
    ) {

        query.project =
            filters.project;

    }


    if (
        allowedFields.includes(
            "activity"
        ) &&
        hasValue(
            filters.activity
        )
    ) {

        query.activity =
            filters.activity;

    }


    if (
        allowedFields.includes(
            "activityRun"
        ) &&
        hasValue(
            filters.activityRun
        )
    ) {

        query.activityRun =
            filters.activityRun;

    }


    if (
        allowedFields.includes(
            "donor"
        ) &&
        hasValue(
            filters.donor
        )
    ) {

        query.donor =
            filters.donor;

    }


    if (
        allowedFields.includes(
            "gender"
        ) &&
        hasValue(
            filters.gender
        )
    ) {

        query.gender =
            filters.gender;

    }


    if (
        allowedFields.includes(
            "status"
        ) &&
        hasValue(
            filters.status
        )
    ) {

        query.status =
            filters.status;

    }


    if (
        allowedFields.includes(
            "participantType"
        ) &&
        hasValue(
            filters.participantType
        )
    ) {

        query.participantType =
            filters.participantType;

    }


    if (
        allowedFields.includes(
            "createdBy"
        ) &&
        hasValue(
            filters.createdBy
        )
    ) {

        query.createdBy =
            filters.createdBy;

    }


    // =================================================
    // SOFT DELETE
    // =================================================

    if (
        options.includeSoftDelete !== false
    ) {

        query.isDeleted =
            false;

    }


    return query;

};


// =====================================================
// BUILD DATE FILTER
// =====================================================
//
// startDate:
// inclusive at 00:00:00.
//
// endDate:
// inclusive for the entire calendar day.
//
// Example:
//
// 2026-09-01 -> $gte September 1 00:00
//
// 2026-09-10 -> $lt September 11 00:00
//
// =====================================================

const buildDateFilter = (
    filters = {},
    field
) => {

    if (
        !field
    ) {

        return {};

    }


    const hasStartDate =
        hasValue(
            filters.startDate
        );

    const hasEndDate =
        hasValue(
            filters.endDate
        );


    if (
        !hasStartDate &&
        !hasEndDate
    ) {

        return {};

    }


    const dateFilter = {};


    // =================================================
    // START DATE
    // =================================================

    if (
        hasStartDate
    ) {

        const startDate =
            parseReportDate(
                filters.startDate
            );


        if (
            startDate
        ) {

            dateFilter.$gte =
                startDate;

        }

    }


    // =================================================
    // END DATE
    // =================================================

    if (
        hasEndDate
    ) {

        const endDate =
            parseReportDate(
                filters.endDate
            );


        if (
            endDate
        ) {

            const nextDay =
                new Date(
                    endDate.getTime()
                );


            nextDay.setDate(
                nextDay.getDate() + 1
            );


            dateFilter.$lt =
                nextDay;

        }

    }


    // =================================================
    // CLEAN EMPTY FILTER
    // =================================================

    if (
        Object.keys(
            dateFilter
        ).length === 0
    ) {

        return {};

    }


    return {

        [field]:
            dateFilter

    };

};


// =====================================================
// REPORT PERIOD
// =====================================================
//
// Supported:
//
// monthly
// quarterly
// semiAnnual
// annual
//
// Custom startDate/endDate takes priority.
//
// =====================================================

const buildPeriodFilter = (
    filters = {},
    field
) => {

    if (
        !field
    ) {

        return {};

    }


    // =================================================
    // CUSTOM DATE RANGE
    // =================================================

    if (
        hasValue(
            filters.startDate
        ) ||
        hasValue(
            filters.endDate
        )
    ) {

        return buildDateFilter(
            filters,
            field
        );

    }


    const {
        period,
        year,
        month,
        quarter,
        half
    } =
        filters;


    if (
        !hasValue(
            period
        )
    ) {

        return {};

    }


    if (
        !hasValue(
            year
        )
    ) {

        return {};

    }


    const numericYear =
        Number(
            year
        );


    if (
        !Number.isInteger(
            numericYear
        )
    ) {

        return {};

    }


    // =================================================
    // ANNUAL RANGE
    // =================================================

    const yearStart =
        new Date(
            numericYear,
            0,
            1,
            0,
            0,
            0,
            0
        );


    const yearEnd =
        new Date(
            numericYear + 1,
            0,
            1,
            0,
            0,
            0,
            0
        );


    // =================================================
    // MONTHLY
    // =================================================

    if (
        period === "monthly"
    ) {

        if (
            !hasValue(
                month
            )
        ) {

            return {};

        }


        const numericMonth =
            Number(
                month
            );


        if (
            !Number.isInteger(
                numericMonth
            ) ||
            numericMonth < 1 ||
            numericMonth > 12
        ) {

            return {};

        }


        const monthStart =
            new Date(
                numericYear,
                numericMonth - 1,
                1,
                0,
                0,
                0,
                0
            );


        const monthEnd =
            new Date(
                numericYear,
                numericMonth,
                1,
                0,
                0,
                0,
                0
            );


        return {

            [field]: {

                $gte:
                    monthStart,

                $lt:
                    monthEnd

            }

        };

    }


    // =================================================
    // QUARTERLY
    // =================================================

    if (
        period === "quarterly"
    ) {

        if (
            !hasValue(
                quarter
            )
        ) {

            return {};

        }


        const numericQuarter =
            Number(
                quarter
            );


        if (
            !Number.isInteger(
                numericQuarter
            ) ||
            numericQuarter < 1 ||
            numericQuarter > 4
        ) {

            return {};

        }


        const quarterStartMonth =
            (
                numericQuarter - 1
            ) * 3;


        const quarterStart =
            new Date(
                numericYear,
                quarterStartMonth,
                1,
                0,
                0,
                0,
                0
            );


        const quarterEnd =
            new Date(
                numericYear,
                quarterStartMonth + 3,
                1,
                0,
                0,
                0,
                0
            );


        return {

            [field]: {

                $gte:
                    quarterStart,

                $lt:
                    quarterEnd

            }

        };

    }


    // =================================================
    // SEMI-ANNUAL
    // =================================================

    if (
        period === "semiAnnual"
    ) {

        if (
            !hasValue(
                half
            )
        ) {

            return {};

        }


        const numericHalf =
            Number(
                half
            );


        if (
            !Number.isInteger(
                numericHalf
            ) ||
            (
                numericHalf !== 1 &&
                numericHalf !== 2
            )
        ) {

            return {};

        }


        const halfStartMonth =
            numericHalf === 1
                ? 0
                : 6;


        const halfEndMonth =
            numericHalf === 1
                ? 6
                : 12;


        const halfStart =
            new Date(
                numericYear,
                halfStartMonth,
                1,
                0,
                0,
                0,
                0
            );


        const halfEnd =
            new Date(
                numericYear,
                halfEndMonth,
                1,
                0,
                0,
                0,
                0
            );


        return {

            [field]: {

                $gte:
                    halfStart,

                $lt:
                    halfEnd

            }

        };

    }


    // =================================================
    // ANNUAL
    // =================================================

    if (
        period === "annual"
    ) {

        return {

            [field]: {

                $gte:
                    yearStart,

                $lt:
                    yearEnd

            }

        };

    }


    return {};

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    buildCommonFilters,

    buildDateFilter,

    buildPeriodFilter

};