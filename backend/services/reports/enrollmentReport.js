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
            .populate("program", "programCode name status")
            .populate({
                path: "beneficiary",
                select: "beneficiaryNumber firstName middleName lastName gender dateOfBirth region",
                populate: { path: "gender", select: "value" }
            })
            .sort({ enrollmentDate: -1 })
            .lean();


    // One flat row per enrollment
    const genderOf = (beneficiary) =>
        beneficiary?.gender?.value || (typeof beneficiary?.gender === "string" ? beneficiary.gender : "Unknown");

    const details =
        enrollments.map(enrollment => ({
            beneficiaryNumber: enrollment.beneficiary?.beneficiaryNumber || "-",
            beneficiary: enrollment.beneficiary
                ? [enrollment.beneficiary.firstName, enrollment.beneficiary.middleName, enrollment.beneficiary.lastName].filter(Boolean).join(" ")
                : "-",
            gender: genderOf(enrollment.beneficiary),
            region: enrollment.beneficiary?.region || "-",
            program: enrollment.program?.name || "-",
            enrollmentDate: enrollment.enrollmentDate,
            status: enrollment.status,
            completionDate: enrollment.completionDate || null
        }));


    // Totals: status, gender, and per program
    const statusSummary = {};
    const genderSummary = {};
    const programs = new Map();

    for (const row of details) {
        statusSummary[row.status] = (statusSummary[row.status] || 0) + 1;
        genderSummary[row.gender] = (genderSummary[row.gender] || 0) + 1;

        if (!programs.has(row.program)) {
            programs.set(row.program, { program: row.program, enrollments: 0, female: 0, male: 0, active: 0, completed: 0, dropped: 0 });
        }
        const program = programs.get(row.program);
        program.enrollments += 1;
        if (row.gender === "Female") program.female += 1;
        if (row.gender === "Male") program.male += 1;
        if (row.status === "Active") program.active += 1;
        if (row.status === "Completed") program.completed += 1;
        if (row.status === "Dropped") program.dropped += 1;
    }

    const byProgram = [...programs.values()].sort((a, b) => b.enrollments - a.enrollments);


    return {

        report: "enrollmentReport",

        title: "Enrollment Report",

        reportTitle: "Enrollment Report",

        generatedAt: new Date(),

        period: {
            startDate: filters.startDate || null,
            endDate: filters.endDate || null,
            year: filters.year || null,
            period: filters.period || null,
            month: filters.month || null,
            quarter: filters.quarter || null,
            half: filters.half || null
        },

        summary: {
            totalEnrollments: details.length,
            female: genderSummary.Female || 0,
            male: genderSummary.Male || 0,
            programs: byProgram.length,
            status: statusSummary
        },

        statistics: {
            byProgram,
            enrollments: details
        },

        charts: {
            enrollmentsByProgram: byProgram.map(item => ({ program: item.program, enrollments: item.enrollments })),
            enrollmentsByGender: Object.entries(genderSummary).map(([gender, enrollments]) => ({ gender, enrollments }))
        },

        details

    };

};


module.exports = {

    generate

};