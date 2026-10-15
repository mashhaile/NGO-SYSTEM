const Activity = require("../../models/Activity");
const ActivityRun = require("../../models/ActivityRun");
const Attendance = require("../../models/Attendance");
const AttendanceRecord = require("../../models/AttendanceRecord");


// =====================================================
// DATE FILTER
// =====================================================

const buildDateFilter = (filters = {}) => {

    let startDate = null;
    let endDate = null;


    // =================================================
    // CUSTOM DATE RANGE
    // =================================================

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


        // MONTHLY

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


        // SIX MONTHLY

        if (
            (
                period === "sixmonthly" ||
                period === "six-monthly" ||
                period === "semiannual" ||
                period === "semi-annual"
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


        // ANNUAL

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
            new Date("9999-12-31");

    }

    return filter;

};


// =====================================================
// MONTH KEY
// =====================================================

const getMonthKey = date => {

    const d =
        new Date(date);

    return (
        `${d.getFullYear()}-` +
        `${String(
            d.getMonth() + 1
        ).padStart(2, "0")}`
    );

};


// =====================================================
// MONTH NAME
// =====================================================

const getMonthName = date => {

    return new Date(
        date
    ).toLocaleString(
        "en-US",
        {
            month: "long"
        }
    );

};


// =====================================================
// GENERATE TRAINING REPORT
// =====================================================

const generate = async (

    filters = {},

    context

) => {


    // =================================================
    // CONTEXT
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
    // DATE FILTER
    // =================================================

    const activityDateFilter =
        buildDateFilter(
            filters
        );


    // =================================================
    // ACTIVITY QUERY
    // =================================================

    const activityQuery = {

        organization:
            organizationId,

        activityType:
            "Training",

        isDeleted:
            false

    };


    // =================================================
    // PROGRAM FILTER
    // =================================================

    if (filters.program) {

        /*
         * Activity itself does not have program.
         * Program is reached through ActivityRun.
         */

    }


    // =================================================
    // PROJECT FILTER
    // =================================================

    if (filters.project) {

        activityQuery.project =
            filters.project;

    }


    // =================================================
    // ACTIVITY FILTER
    // =================================================

    if (filters.activity) {

        activityQuery._id =
            filters.activity;

    }


    // =================================================
    // DATE FILTER
    // =================================================

    if (
        Object.keys(
            activityDateFilter
        ).length
    ) {

        activityQuery.activityDate =
            activityDateFilter;

    }


    // =================================================
    // STATUS
    // =================================================

    if (filters.status) {

        activityQuery.status =
            filters.status;

    }


    // =================================================
    // GET TRAININGS
    // =================================================

    const trainings =
        await Activity.find(
            activityQuery
        )

        .populate(
            "project",
            "projectCode name status program"
        )

        .sort({
            activityDate: -1
        });


    // =================================================
    // TRAINING IDs
    // =================================================

    const trainingIds =
        trainings.map(
            training =>
                training._id
        );


    // =================================================
    // GET RUNS
    // =================================================

    let runs = [];

    if (trainingIds.length > 0) {

        const runQuery = {

            organization:
                organizationId,

            activity: {
                $in: trainingIds
            },

            isDeleted:
                false

        };


        if (filters.project) {

            runQuery.project =
                filters.project;

        }


        if (filters.program) {

            runQuery.program =
                filters.program;

        }


        runs =
            await ActivityRun.find(
                runQuery
            )

            .populate(
                "project",
                "projectCode name"
            )

            .populate(
                "program",
                "programCode name"
            )

            .sort({
                startDate: -1
            });

    }


    // =================================================
    // RUN IDS
    // =================================================

    const runIds =
        runs.map(
            run =>
                run._id
        );


    // =================================================
    // ATTENDANCE
    // =================================================

    let attendance = [];

    if (runIds.length > 0) {

        attendance =
            await Attendance.find({

                organization:
                    organizationId,

                activityRun: {
                    $in: runIds
                },

                isDeleted:
                    false

            })

            .sort({
                sessionDate: -1
            });

    }


    // =================================================
    // ATTENDANCE RECORDS
    // =================================================

    let attendanceRecords = [];

    if (attendance.length > 0) {

        const attendanceIds =
            attendance.map(
                item =>
                    item._id
            );


        attendanceRecords =
            await AttendanceRecord.find({

                organization:
                    organizationId,

                attendance: {
                    $in: attendanceIds
                },

                isDeleted:
                    false

            });

    }


    // =================================================
    // MAP RUNS
    // =================================================

    const runsByActivity =
        new Map();


    runs.forEach(
        run => {

            const key =
                String(
                    run.activity
                );


            if (
                !runsByActivity.has(key)
            ) {

                runsByActivity.set(
                    key,
                    []
                );

            }


            runsByActivity
                .get(key)
                .push(run);

        }
    );


    // =================================================
    // MAP ATTENDANCE
    // =================================================

    const attendanceByRun =
        new Map();


    attendance.forEach(
        session => {

            const key =
                String(
                    session.activityRun
                );


            if (
                !attendanceByRun.has(key)
            ) {

                attendanceByRun.set(
                    key,
                    []
                );

            }


            attendanceByRun
                .get(key)
                .push(session);

        }
    );


    // =================================================
    // MAP RECORDS
    // =================================================

    const recordsByAttendance =
        new Map();


    attendanceRecords.forEach(
        record => {

            const key =
                String(
                    record.attendance
                );


            if (
                !recordsByAttendance.has(key)
            ) {

                recordsByAttendance.set(
                    key,
                    []
                );

            }


            recordsByAttendance
                .get(key)
                .push(record);

        }
    );


    // =================================================
    // MONTHLY MAP
    // =================================================

    const monthlyMap =
        new Map();


    // =================================================
    // TRAINING ROWS
    // =================================================

    const rows = [];


    // =================================================
    // GLOBAL SETS
    // =================================================

    const beneficiarySet =
        new Set();

    const participantSet =
        new Set();


    // =================================================
    // PROCESS TRAININGS
    // =================================================

    for (
        const training
        of trainings
    ) {


        const trainingRuns =
            runsByActivity.get(
                String(
                    training._id
                )
            ) || [];


        let totalSessions = 0;

        let totalParticipants = 0;

        let present = 0;

        let absent = 0;

        let late = 0;

        let excused = 0;


        const trainingParticipants =
            new Set();


        // =============================================
        // PROCESS RUNS
        // =============================================

        for (
            const run
            of trainingRuns
        ) {

            const sessions =
                attendanceByRun.get(
                    String(
                        run._id
                    )
                ) || [];


            totalSessions +=
                sessions.length;


            // =========================================
            // PROCESS SESSIONS
            // =========================================

            for (
                const session
                of sessions
            ) {

                const records =
                    recordsByAttendance.get(
                        String(
                            session._id
                        )
                    ) || [];


                totalParticipants +=
                    records.length;


                records.forEach(
                    record => {

                        if (
                            record.beneficiary
                        ) {

                            const beneficiaryId =
                                String(
                                    record.beneficiary
                                );

                            beneficiarySet.add(
                                beneficiaryId
                            );

                            trainingParticipants.add(
                                beneficiaryId
                            );

                        }


                        const participantKey =
                            record.beneficiary ||
                            record.staff ||
                            record.board ||
                            record.externalParticipant?.name;


                        if (participantKey) {

                            participantSet.add(
                                String(
                                    participantKey
                                )
                            );

                        }


                        switch (
                            record.status
                        ) {

                            case "Present":

                                present++;

                                break;


                            case "Absent":

                                absent++;

                                break;


                            case "Late":

                                late++;

                                break;


                            case "Excused":

                                excused++;

                                break;

                        }

                    }
                );

            }

        }


        // =============================================
        // MONTHLY
        // =============================================

        if (
            training.activityDate
        ) {

            const date =
                new Date(
                    training.activityDate
                );


            const key =
                getMonthKey(
                    date
                );


            if (
                !monthlyMap.has(key)
            ) {

                monthlyMap.set(
                    key,
                    {

                        year:
                            date.getFullYear(),

                        month:
                            date.getMonth() + 1,

                        monthName:
                            getMonthName(date),

                        trainings:
                            0,

                        targetParticipants:
                            0,

                        runs:
                            0,

                        sessions:
                            0,

                        participants:
                            0,

                        beneficiaries:
                            new Set(),

                        present:
                            0,

                        absent:
                            0,

                        late:
                            0,

                        excused:
                            0

                    }
                );

            }


            const monthly =
                monthlyMap.get(key);


            monthly.trainings += 1;

            monthly.targetParticipants +=
                Number(
                    training.targetParticipants ||
                    0
                );

            monthly.runs +=
                trainingRuns.length;

            monthly.sessions +=
                totalSessions;

            monthly.participants +=
                totalParticipants;

            monthly.present +=
                present;

            monthly.absent +=
                absent;

            monthly.late +=
                late;

            monthly.excused +=
                excused;


            trainingParticipants.forEach(
                id =>
                    monthly.beneficiaries.add(id)
            );

        }


        // =============================================
        // ROW
        // =============================================

        rows.push({

            trainingId:
                training._id,

            activityCode:
                training.activityCode,

            name:
                training.name,

            activityType:
                training.activityType,

            activityDate:
                training.activityDate,

            status:
                training.status,

            description:
                training.description,

            location:
                training.location,

            facilitator:
                training.facilitator,

            targetParticipants:
                Number(
                    training.targetParticipants ||
                    0
                ),

            project:
                training.project
                    ? {

                        id:
                            training.project._id,

                        projectCode:
                            training.project.projectCode,

                        name:
                            training.project.name,

                        status:
                            training.project.status

                    }
                    : null,

            runs:
                trainingRuns.length,

            sessions:
                totalSessions,

            participants:
                totalParticipants,

            beneficiaries:
                trainingParticipants.size,

            attendance: {

                present,

                absent,

                late,

                excused

            }

        });

    }


    // =================================================
    // MONTHLY OUTPUT
    // =================================================

    const monthly =
        Array.from(
            monthlyMap.values()
        )
        .map(
            item => ({

                ...item,

                beneficiaries:
                    item.beneficiaries.size

            })
        )
        .sort(
            (a, b) =>
                (
                    a.year * 100 +
                    a.month
                ) -
                (
                    b.year * 100 +
                    b.month
                )
        );


    // =================================================
    // GLOBAL TOTALS
    // =================================================

    const totalTargetParticipants =
        trainings.reduce(

            (
                total,
                training
            ) =>
                total +
                Number(
                    training.targetParticipants ||
                    0
                ),

            0

        );


    const totalRuns =
        runs.length;


    const totalSessions =
        attendance.length;


    const totalParticipants =
        attendanceRecords.length;


    const totalPresent =
        attendanceRecords.filter(
            record =>
                record.status === "Present"
        ).length;


    const totalAbsent =
        attendanceRecords.filter(
            record =>
                record.status === "Absent"
        ).length;


    const totalLate =
        attendanceRecords.filter(
            record =>
                record.status === "Late"
        ).length;


    const totalExcused =
        attendanceRecords.filter(
            record =>
                record.status === "Excused"
        ).length;


    const attendanceRate =
        totalParticipants > 0
            ? (
                (
                    totalPresent +
                    totalLate
                ) /
                totalParticipants
            ) * 100
            : 0;


    // =================================================
    // STATUS BREAKDOWN
    // =================================================

    const statusMap =
        new Map();


    trainings.forEach(
        training => {

            const status =
                training.status ||
                "Unknown";


            statusMap.set(

                status,

                (
                    statusMap.get(status) ||
                    0
                ) + 1

            );

        }
    );


    const statuses =
        Array.from(
            statusMap.entries()
        )
        .map(
            ([status, count]) => ({

                status,

                count

            })
        );


    // =================================================
    // FINAL REPORT
    // =================================================

    return {

        report:
            "trainingReport",

        reportTitle:
            "Training Report",

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


        filters: {

            program:
                filters.program ||
                null,

            project:
                filters.project ||
                null,

            activity:
                filters.activity ||
                null,

            status:
                filters.status ||
                null

        },


        summary: {

            totalTrainings:
                trainings.length,

            totalTargetParticipants,

            totalRuns,

            totalSessions,

            totalParticipants,

            totalBeneficiaries:
                beneficiarySet.size,

            totalUniqueParticipants:
                participantSet.size,

            present:
                totalPresent,

            absent:
                totalAbsent,

            late:
                totalLate,

            excused:
                totalExcused,

            attendanceRate:

                Number(
                    attendanceRate.toFixed(2)
                )

        },


        statuses,


        monthly,


        data:
            rows

    };

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    generate

};