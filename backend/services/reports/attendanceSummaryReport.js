const Attendance = require("../../models/Attendance");
const AttendanceRecord = require("../../models/AttendanceRecord");

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


    // MONTHLY
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


    // QUARTERLY
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


    // SIX MONTH
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


    // ANNUAL
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
// GENERATE SUMMARY REPORT
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
// ATTENDANCE SESSIONS
// =================================================

const attendanceQuery = {

    organization:
        organizationId,

    isDeleted:
        false

};


if (filters.program) {

    attendanceQuery.program =
        filters.program;

}


if (filters.project) {

    attendanceQuery.project =
        filters.project;

}


if (filters.activityRun) {

    attendanceQuery.activityRun =
        filters.activityRun;

}


const dateFilter =
    buildDateFilter(filters);


if (Object.keys(dateFilter).length) {

    attendanceQuery.sessionDate =
        dateFilter;

}


const sessions =
    await Attendance.find(
        attendanceQuery
    )

    .populate(
        "program",
        "programCode name"
    )

    .populate(
        "project",
        "projectCode name"
    )

    .sort({
        sessionDate: -1
    });


const sessionIds =
    sessions.map(
        session =>
            session._id
    );


// =================================================
// RECORDS
// =================================================

let records = [];


if (sessionIds.length) {

    const recordQuery = {

        organization:
            organizationId,

        attendance: {
            $in:
                sessionIds
        },

        isDeleted:
            false

    };


    if (filters.participantType) {

        recordQuery.participantType =
            filters.participantType;

    }


    if (filters.status) {

        recordQuery.status =
            filters.status;

    }


    records =
        await AttendanceRecord.find(
            recordQuery
        );

}


// =================================================
// GENERAL COUNTERS
// =================================================

const status = {

    Present: 0,

    Absent: 0,

    Late: 0,

    Excused: 0

};


const participantTypes = {};

const genders = {};

const ageGroups = {};

const disability = {

    withDisability: 0,

    withoutDisability: 0

};


const programs = {};

const projects = {};


records.forEach(record => {

    // Status

    if (
        Object.prototype.hasOwnProperty.call(
            status,
            record.status
        )
    ) {

        status[record.status]++;

    }


    // Participant type

    participantTypes[
        record.participantType
    ] =
        (
            participantTypes[
                record.participantType
            ] || 0
        ) + 1;


    // Gender

    const gender =
        record.gender || "Unknown";

    genders[gender] =
        (genders[gender] || 0) + 1;


    // Age group

    const ageGroup =
        record.ageGroup || "Unknown";

    ageGroups[ageGroup] =
        (ageGroups[ageGroup] || 0) + 1;


    // Disability

    if (record.disabilityStatus) {

        disability.withDisability++;

    }
    else {

        disability.withoutDisability++;

    }

});


// =================================================
// SESSION-LEVEL PROGRAM / PROJECT SUMMARY
// =================================================

sessions.forEach(session => {

    const sessionRecords =
        records.filter(
            record =>
                String(
                    record.attendance
                ) ===
                String(
                    session._id
                )
        );


    const programId =
        session.program?._id
            ? String(
                session.program._id
            )
            : "unknown";


    const projectId =
        session.project?._id
            ? String(
                session.project._id
            )
            : "unknown";


    if (!programs[programId]) {

        programs[programId] = {

            id:
                session.program?._id || null,

            programCode:
                session.program?.programCode || null,

            name:
                session.program?.name || "Unknown",

            sessions: 0,

            participants: 0,

            present: 0,

            absent: 0,

            late: 0,

            excused: 0

        };

    }


    programs[programId].sessions++;

    programs[programId].participants +=
        sessionRecords.length;


    sessionRecords.forEach(record => {

        if (
            programs[programId][
                record.status.toLowerCase()
            ] !== undefined
        ) {

            programs[programId][
                record.status.toLowerCase()
            ]++;

        }

    });


    if (!projects[projectId]) {

        projects[projectId] = {

            id:
                session.project?._id || null,

            projectCode:
                session.project?.projectCode || null,

            name:
                session.project?.name || "Unknown",

            sessions: 0,

            participants: 0,

            present: 0,

            absent: 0,

            late: 0,

            excused: 0

        };

    }


    projects[projectId].sessions++;

    projects[projectId].participants +=
        sessionRecords.length;


    sessionRecords.forEach(record => {

        const key =
            record.status.toLowerCase();

        if (
            projects[projectId][key] !== undefined
        ) {

            projects[projectId][key]++;

        }

    });

});


// =================================================
// ATTENDANCE RATE
// =================================================

const totalRecords =
    records.length;


const attendanceRate =
    totalRecords > 0
        ? Number(
            (
                (
                    status.Present +
                    status.Late
                ) /
                totalRecords
            ) *
            100
        ).toFixed(2)
        : 0;


// =================================================
// RETURN
// =================================================

return {

    report:
        "attendanceSummaryReport",

    reportTitle:
        "Attendance Summary Report",

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

        totalSessions:
            sessions.length,

        totalParticipants:
            totalRecords,

        attendanceRate,

        status,

        participantTypes,

        genders,

        ageGroups,

        disability

    },

    byProgram:
        Object.values(programs),

    byProject:
        Object.values(projects)

};

};

module.exports = {

generate

};
