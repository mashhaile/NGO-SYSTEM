const Enrollment =
    require("../../models/enrollment");


// =====================================================
// DATE FILTER
// =====================================================

const buildDateFilter = (filters = {}) => {

    let startDate = null;
    let endDate = null;


    if (filters.startDate) {

        startDate =
            new Date(filters.startDate);

    }


    if (filters.endDate) {

        endDate =
            new Date(filters.endDate);

        endDate.setDate(
            endDate.getDate() + 1
        );

    }


    if (
        filters.year &&
        !filters.startDate &&
        !filters.endDate
    ) {

        const year =
            Number(filters.year);

        if (!Number.isNaN(year)) {

            startDate =
                new Date(year, 0, 1);

            endDate =
                new Date(year + 1, 0, 1);

        }

    }


    if (
        filters.period &&
        filters.year
    ) {

        const year =
            Number(filters.year);

        const period =
            String(filters.period)
                .toLowerCase();


        if (
            period === "monthly" &&
            filters.month
        ) {

            const month =
                Number(filters.month) - 1;

            startDate =
                new Date(year, month, 1);

            endDate =
                new Date(year, month + 1, 1);

        }


        if (
            period === "quarterly" &&
            filters.quarter
        ) {

            const quarter =
                Number(filters.quarter);

            const month =
                (quarter - 1) * 3;

            startDate =
                new Date(year, month, 1);

            endDate =
                new Date(year, month + 3, 1);

        }


        if (
            [
                "semiannual",
                "semi-annual",
                "sixmonthly",
                "six-monthly"
            ].includes(period) &&
            filters.half
        ) {

            const half =
                Number(filters.half);

            if (half === 1) {

                startDate =
                    new Date(year, 0, 1);

                endDate =
                    new Date(year, 6, 1);

            }

            if (half === 2) {

                startDate =
                    new Date(year, 6, 1);

                endDate =
                    new Date(year + 1, 0, 1);

            }

        }


        if (
            period === "annual" ||
            period === "yearly"
        ) {

            startDate =
                new Date(year, 0, 1);

            endDate =
                new Date(year + 1, 0, 1);

        }

    }


    const filter = {};

    if (startDate || endDate) {

        filter.$gte =
            startDate || new Date(0);

        filter.$lt =
            endDate || new Date("9999-12-31");

    }

    return filter;

};


// =====================================================
// GENERATE
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


    const query = {

        organization:
            context.organizationId,

        isDeleted:
            false

    };


    if (filters.program) {

        query.program =
            filters.program;

    }


    if (filters.beneficiary) {

        query.beneficiary =
            filters.beneficiary;

    }


    if (filters.status) {

        query.status =
            filters.status;

    }


    const dateFilter =
        buildDateFilter(filters);


    if (Object.keys(dateFilter).length) {

        query.enrollmentDate =
            dateFilter;

    }


    const enrollments =
        await Enrollment.find(query)

            .populate(
                "program",
                "programCode name status"
            )

            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName gender dateOfBirth"
            )

            .sort({
                enrollmentDate: -1
            });


    const rows =
        enrollments.map(enrollment => ({

            id:
                enrollment._id,

            enrollmentDate:
                enrollment.enrollmentDate,

            status:
                enrollment.status,

            completionDate:
                enrollment.completionDate,

            exitReason:
                enrollment.exitReason,

            remarks:
                enrollment.remarks,

            program:
                enrollment.program
                    ? {

                        id:
                            enrollment.program._id,

                        programCode:
                            enrollment.program.programCode,

                        name:
                            enrollment.program.name,

                        status:
                            enrollment.program.status

                    }
                    : null,

            beneficiary:
                enrollment.beneficiary
                    ? {

                        id:
                            enrollment.beneficiary._id,

                        beneficiaryNumber:
                            enrollment.beneficiary.beneficiaryNumber,

                        name:
                            [
                                enrollment.beneficiary.firstName,
                                enrollment.beneficiary.middleName,
                                enrollment.beneficiary.lastName
                            ]
                            .filter(Boolean)
                            .join(" "),

                        gender:
                            enrollment.beneficiary.gender,

                        dateOfBirth:
                            enrollment.beneficiary.dateOfBirth

                    }
                    : null

        }));


    const statusSummary = {};

    rows.forEach(row => {

        statusSummary[row.status] =
            (statusSummary[row.status] || 0) + 1;

    });


    return {

        report:
            "enrollmentReport",

        reportTitle:
            "Enrollment Report",

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

            totalEnrollments:
                rows.length,

            status:
                statusSummary

        },

        data:
            rows

    };

};


module.exports = {

    generate

};