const Activity = require("../../models/Activity");
const ActivityRun = require("../../models/ActivityRun");
const Attendance = require("../../models/Attendance");
const AttendanceRecord = require("../../models/AttendanceRecord");
const Project = require("../../models/Project");

const {
    buildDateFilter,
    applyLocationFilter,
    getLocationFilterSummary
} = require("./reportFilters");


// =====================================================
// PARTICIPANT TYPES
// =====================================================

const PARTICIPANT_TYPES = [
    "Beneficiary",
    "Staff",
    "Board",
    "Partner",
    "Government",
    "Community",
    "Other"
];


// =====================================================
// EXTERNAL PARTICIPANT TYPES
// =====================================================

const EXTERNAL_PARTICIPANT_TYPES = [
    "Board",
    "Partner",
    "Government",
    "Community",
    "Other"
];


// =====================================================
// SAFE FULL NAME
// =====================================================

const buildFullName = (
    person
) => {

    if (!person) {

        return null;

    }

    if (
        person.name
    ) {

        return (
            String(
                person.name
            )
                .trim() ||
            null
        );

    }

    return [
        person.firstName,
        person.middleName,
        person.lastName
    ]
        .filter(Boolean)
        .join(" ")
        .trim() || null;

};


// =====================================================
// EXTERNAL PARTICIPANT KEY
// =====================================================

const getExternalParticipantKey = (
    record
) => {

    const external =
        record.externalParticipant ||
        {};

    const name =
        String(
            external.name ||
            ""
        )
            .trim()
            .toLowerCase();

    const organizationName =
        String(
            external.organizationName ||
            ""
        )
            .trim()
            .toLowerCase();

    const position =
        String(
            external.position ||
            ""
        )
            .trim()
            .toLowerCase();

    const phone =
        String(
            external.phone ||
            ""
        )
            .trim()
            .toLowerCase();

    const email =
        String(
            external.email ||
            ""
        )
            .trim()
            .toLowerCase();

    const externalKey = [
        name,
        organizationName,
        position,
        phone,
        email
    ]
        .join("|");

    if (
        externalKey ===
        "||||"
    ) {

        return null;

    }

    return (
        record.participantType +
        ":" +
        externalKey
    );

};


// =====================================================
// PARTICIPANT KEY
// =====================================================

const getParticipantKey = (
    record
) => {

    if (
        record.participantType ===
        "Beneficiary" &&
        record.beneficiary
    ) {

        return (
            "Beneficiary:" +
            String(
                record.beneficiary._id
            )
        );

    }

    if (
        record.participantType ===
        "Staff" &&
        record.staff
    ) {

        return (
            "Staff:" +
            String(
                record.staff._id
            )
        );

    }

    if (
        EXTERNAL_PARTICIPANT_TYPES.includes(
            record.participantType
        )
    ) {

        const externalKey =
            getExternalParticipantKey(
                record
            );

        if (
            externalKey
        ) {

            return externalKey;

        }

    }

    return (
        record.participantType +
        ":" +
        String(
            record._id
        )
    );

};


// =====================================================
// PARTICIPANT DISPLAY
// =====================================================

const buildParticipant = (
    record
) => {

    const participantType =
        record.participantType;


    if (
        participantType ===
        "Beneficiary"
    ) {

        const beneficiaryGender =
            record.beneficiary &&
            record.beneficiary.gender
                ? (
                    record.beneficiary.gender.value ||
                    record.beneficiary.gender.code ||
                    null
                )
                : null;

        return {

            attendanceRecordId:
                record._id,

            participantType:
                participantType,

            participantId:
                record.beneficiary
                    ? record.beneficiary._id
                    : null,

            participantNumber:
                record.beneficiary
                    ? record.beneficiary.beneficiaryNumber
                    : null,

            participantName:
                record.beneficiary
                    ? buildFullName(
                        record.beneficiary
                    )
                    : null,

            gender:
                record.gender ||
                beneficiaryGender ||
                null,

            ageGroup:
                record.ageGroup ||
                null,

            disabilityStatus:
                Boolean(
                    record.disabilityStatus
                ),

            beneficiaryStatus:
                record.beneficiary
                    ? record.beneficiary.status
                    : null,

            phone:
                record.beneficiary
                    ? record.beneficiary.phone || null
                    : null,

            organizationName:
                null,

            position:
                null,

            email:
                record.beneficiary
                    ? record.beneficiary.email || null
                    : null,

            location:
                record.location ||
                null,

            status:
                record.status,

            checkInTime:
                record.checkInTime ||
                null,

            checkOutTime:
                record.checkOutTime ||
                null,

            notes:
                record.notes ||
                null

        };

    }


    if (
        participantType ===
        "Staff"
    ) {

        return {

            attendanceRecordId:
                record._id,

            participantType:
                participantType,

            participantId:
                record.staff
                    ? record.staff._id
                    : null,

            participantNumber:
                null,

            participantName:
                record.staff
                    ? buildFullName(
                        record.staff
                    )
                    : null,

            gender:
                record.gender ||
                null,

            ageGroup:
                record.ageGroup ||
                null,

            disabilityStatus:
                Boolean(
                    record.disabilityStatus
                ),

            beneficiaryStatus:
                null,

            phone:
                null,

            organizationName:
                null,

            position:
                null,

            email:
                record.staff
                    ? record.staff.email || null
                    : null,

            location:
                record.location ||
                null,

            status:
                record.status,

            checkInTime:
                record.checkInTime ||
                null,

            checkOutTime:
                record.checkOutTime ||
                null,

            notes:
                record.notes ||
                null

        };

    }


    if (
        EXTERNAL_PARTICIPANT_TYPES.includes(
            participantType
        )
    ) {

        const external =
            record.externalParticipant ||
            {};

        return {

            attendanceRecordId:
                record._id,

            participantType:
                participantType,

            participantId:
                null,

            participantNumber:
                null,

            participantName:
                external.name ||
                null,

            gender:
                record.gender ||
                external.gender ||
                null,

            ageGroup:
                record.ageGroup ||
                null,

            disabilityStatus:
                Boolean(
                    record.disabilityStatus
                ),

            beneficiaryStatus:
                null,

            phone:
                external.phone ||
                null,

            organizationName:
                external.organizationName ||
                null,

            position:
                external.position ||
                null,

            email:
                external.email ||
                null,

            location:
                record.location ||
                null,

            status:
                record.status,

            checkInTime:
                record.checkInTime ||
                null,

            checkOutTime:
                record.checkOutTime ||
                null,

            notes:
                record.notes ||
                null

        };

    }


    return {

        attendanceRecordId:
            record._id,

        participantType:
            participantType,

        participantId:
            null,

        participantNumber:
            null,

        participantName:
            null,

        gender:
            record.gender ||
            null,

        ageGroup:
            record.ageGroup ||
            null,

        disabilityStatus:
            Boolean(
                record.disabilityStatus
            ),

        beneficiaryStatus:
            null,

        phone:
            null,

        organizationName:
            null,

        position:
            null,

        email:
            null,

        location:
            record.location ||
            null,

        status:
            record.status,

        checkInTime:
            record.checkInTime ||
            null,

        checkOutTime:
            record.checkOutTime ||
            null,

        notes:
            record.notes ||
            null

    };

};


// =====================================================
// GENERATE ACTIVITY REPORT
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
    // SELECTED ACTIVITY FILTER
    // =================================================

    let selectedActivityIds =
        null;


    if (
        filters.activity
    ) {

        selectedActivityIds = [
            filters.activity
        ];

    }


    // =================================================
    // ACTIVITY RUN FILTER
    // =================================================

    if (
        filters.activityRun
    ) {

        const selectedActivityRun =
            await ActivityRun.findOne(
                {
                    _id:
                        filters.activityRun,

                    organization:
                        organizationId,

                    isDeleted:
                        false
                }
            )
                .select("activity")
                .lean();


        if (
            !selectedActivityRun
        ) {

            selectedActivityIds = [];

        }

        else {

            const activityId =
                selectedActivityRun.activity;


            if (
                selectedActivityIds
            ) {

                selectedActivityIds =
                    selectedActivityIds.filter(
                        activityIdItem =>
                            String(
                                activityIdItem
                            ) ===
                            String(
                                activityId
                            )
                    );

            }

            else {

                selectedActivityIds = [
                    activityId
                ];

            }

        }

    }


    // =================================================
    // QUERY
    // =================================================

    const query = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // SELECTED ACTIVITY IDS
    // =================================================

    if (
        selectedActivityIds
    ) {

        query._id = {

            $in:
                selectedActivityIds

        };

    }


    // =================================================
    // PROGRAM FILTER
    // =================================================

    if (
        filters.program
    ) {

        const programProjects =
            await Project.find(
                {
                    organization:
                        organizationId,

                    program:
                        filters.program,

                    isDeleted:
                        false
                }
            )
                .select("_id")
                .lean();


        const programProjectIds =
            programProjects.map(
                project =>
                    project._id
            );


        query.project = {

            $in:
                programProjectIds

        };

    }


    // =================================================
    // PROJECT FILTER
    // =================================================

    if (
        filters.project
    ) {

        if (
            query.project &&
            query.project.$in
        ) {

            query.project = {

                $in:
                    query.project.$in.filter(
                        projectId =>
                            String(
                                projectId
                            ) ===
                            String(
                                filters.project
                            )
                    )

            };

        }

        else {

            query.project =
                filters.project;

        }

    }


    // =================================================
    // STATUS FILTER
    // =================================================

    if (
        filters.status
    ) {

        query.status =
            filters.status;

    }


    // =================================================
    // LOCATION FILTER
    // =================================================

    applyLocationFilter(
        query,
        filters
    );


    // =================================================
    // ACTIVITY TYPE FILTER
    // =================================================

    if (
        filters.activityType
    ) {

        query.activityType =
            filters.activityType;

    }


    // =================================================
    // PARTICIPANT SOURCE FILTER
    // =================================================

    if (
        filters.participantSource
    ) {

        query.participantSource =
            filters.participantSource;

    }


    // =================================================
    // DATE FILTER
    // =================================================

    const dateFilter =
        buildDateFilter(
            filters
        );


    if (
        Object.keys(
            dateFilter
        ).length
    ) {

        query.activityDate =
            dateFilter;

    }


    // =================================================
    // ACTIVITIES
    // =================================================

    const activities =
        await Activity.find(
            query
        )

            .populate(
                {
                    path:
                        "project",

                    select:
                        "projectCode name status program",

                    populate:
                        {

                            path:
                                "program",

                            select:
                                "programCode name status"

                        }

                }
            )

            .sort(
                {
                    activityDate:
                        -1,

                    name:
                        1

                }
            );


    // =================================================
    // ACTIVITY IDS
    // =================================================

    const activityIds =
        activities.map(
            activity =>
                activity._id
        );


    // =================================================
    // ACTIVITY RUN QUERY
    // =================================================

    const activityRunQuery = {

        organization:
            organizationId,

        isDeleted:
            false,

        activity:
            {
                $in:
                    activityIds
            }

    };


    if (
        filters.activityRun
    ) {

        activityRunQuery._id =
            filters.activityRun;

    }


    // =================================================
    // ACTIVITY RUNS
    // =================================================

    let activityRuns = [];


    if (
        activityIds.length
    ) {

        activityRuns =
            await ActivityRun.find(
                activityRunQuery
            )

                .populate(
                    {
                        path:
                            "program",

                        select:
                            "programCode name status"

                    }
                )

                .populate(
                    {
                        path:
                            "project",

                        select:
                            "projectCode name status"

                    }
                )

                .populate(
                    {
                        path:
                            "activity",

                        select:
                            "activityCode name activityType"

                    }
                )

                .populate(
                    {
                        path:
                            "trainer",

                        select:
                            "name email"

                    }
                )

                .sort(
                    {
                        startDate:
                            -1,

                        name:
                            1

                    }
                );

    }


    // =================================================
    // ACTIVITY RUN IDS
    // =================================================

    const activityRunIds =
        activityRuns.map(
            activityRun =>
                activityRun._id
        );


    // =================================================
    // ATTENDANCE SESSIONS
    // =================================================

    let attendanceSessions = [];


    if (
        activityRunIds.length
    ) {

        attendanceSessions =
            await Attendance.find(
                {
                    organization:
                        organizationId,

                    activityRun:
                        {
                            $in:
                                activityRunIds
                        },

                    isDeleted:
                        false

                }
            )

                .sort(
                    {
                        sessionDate:
                            -1

                    }
                );

    }


    // =================================================
    // ATTENDANCE SESSION IDS
    // =================================================

    const attendanceIds =
        attendanceSessions.map(
            attendance =>
                attendance._id
        );


    // =================================================
    // ATTENDANCE RECORDS
    // =================================================

    let attendanceRecords = [];


    if (
        attendanceIds.length
    ) {

        attendanceRecords =
            await AttendanceRecord.find(
                {
                    organization:
                        organizationId,

                    attendance:
                        {
                            $in:
                                attendanceIds
                        },

                    isDeleted:
                        false
                }
            )

                .populate(
                    {
                        path:
                            "beneficiary",

                        select:
                            "beneficiaryNumber firstName middleName lastName gender dateOfBirth phone email status",

                        populate:
                            {
                                path:
                                    "gender",

                                select:
                                    "value code"

                            }

                    }
                )

                .populate(
                    {
                        path:
                            "staff",

                        select:
                            "name email"

                    }
                )

                .populate(
                    {
                        path:
                            "attendance",

                        select:
                            "sessionTitle sessionNumber sessionDate activityRun"

                    }
                )

                .populate(
                    {
                        path:
                            "activityRun",

                        select:
                            "runCode name startDate endDate region zone woreda location activity project program"

                    }
                )

                .sort(
                    {
                        createdAt:
                            -1

                    }
                );

    }


    // =================================================
    // INDEX ACTIVITY RUNS
    // =================================================

    const activityRunsByActivity = {};


    activityRuns.forEach(
        activityRun => {

            const activityId =
                String(
                    activityRun.activity
                        ? activityRun.activity._id
                        : activityRun.activity
                );


            if (
                !activityRunsByActivity[
                    activityId
                ]
            ) {

                activityRunsByActivity[
                    activityId
                ] = [];

            }


            activityRunsByActivity[
                activityId
            ].push(
                activityRun
            );

        }
    );


    // =================================================
    // INDEX ATTENDANCE SESSIONS
    // =================================================

    const attendanceByRun = {};


    attendanceSessions.forEach(
        attendance => {

            const activityRunId =
                String(
                    attendance.activityRun
                );


            if (
                !attendanceByRun[
                    activityRunId
                ]
            ) {

                attendanceByRun[
                    activityRunId
                ] = [];

            }


            attendanceByRun[
                activityRunId
            ].push(
                attendance
            );

        }
    );


    // =================================================
    // INDEX ATTENDANCE RECORDS
    // =================================================

    const recordsByRun = {};


    attendanceRecords.forEach(
        record => {

            const activityRunId =
                record.activityRun
                    ? record.activityRun._id
                    : record.activityRun;


            if (
                !activityRunId
            ) {

                return;

            }


            const key =
                String(
                    activityRunId
                );


            if (
                !recordsByRun[
                    key
                ]
            ) {

                recordsByRun[
                    key
                ] = [];

            }


            recordsByRun[
                key
            ].push(
                record
            );

        }
    );


    // =================================================
    // ROWS
    // =================================================

    const rows =
        activities.map(
            activity => {

                const activityId =
                    String(
                        activity._id
                    );


                const program =
                    activity.project &&
                    activity.project.program
                        ? {

                            id:
                                activity.project.program._id,

                            programCode:
                                activity.project.program.programCode,

                            name:
                                activity.project.program.name,

                            status:
                                activity.project.program.status

                        }
                        : null;


                const project =
                    activity.project
                        ? {

                            id:
                                activity.project._id,

                            projectCode:
                                activity.project.projectCode,

                            name:
                                activity.project.name,

                            status:
                                activity.project.status

                        }
                        : null;


                const activityRunDocuments =
                    activityRunsByActivity[
                        activityId
                    ] || [];


                // =====================================
                // ACTIVITY PARTICIPANTS
                // =====================================

                const participantMap =
                    new Map();


                const beneficiaryMap =
                    new Map();


                const participantTypeSummary = {};


                let present =
                    0;


                let absent =
                    0;


                let late =
                    0;


                let excused =
                    0;


                const runRows =
                    activityRunDocuments.map(
                        activityRun => {

                            const runId =
                                String(
                                    activityRun._id
                                );


                            const sessionDocuments =
                                attendanceByRun[
                                    runId
                                ] || [];


                            const runRecords =
                                recordsByRun[
                                    runId
                                ] || [];


                            const runParticipantMap =
                                new Map();


                            const runBeneficiaryMap =
                                new Map();


                            const runParticipantTypeSummary =
                                {};


                            let runPresent =
                                0;


                            let runAbsent =
                                0;


                            let runLate =
                                0;


                            let runExcused =
                                0;


                            runRecords.forEach(
                                record => {

                                    const participant =
                                        buildParticipant(
                                            record
                                        );


                                    const participantKey =
                                        getParticipantKey(
                                            record
                                        );


                                    if (
                                        !runParticipantMap.has(
                                            participantKey
                                        )
                                    ) {

                                        runParticipantMap.set(
                                            participantKey,
                                            participant
                                        );

                                    }


                                    if (
                                        !participantTypeSummary[
                                            record.participantType
                                        ]
                                    ) {

                                        participantTypeSummary[
                                            record.participantType
                                        ] =
                                            0;

                                    }


                                    participantTypeSummary[
                                        record.participantType
                                    ] +=
                                        1;


                                    if (
                                        !runParticipantTypeSummary[
                                            record.participantType
                                        ]
                                    ) {

                                        runParticipantTypeSummary[
                                            record.participantType
                                        ] =
                                            0;

                                    }


                                    runParticipantTypeSummary[
                                        record.participantType
                                    ] +=
                                        1;


                                    if (
                                        record.status ===
                                        "Present"
                                    ) {

                                        present +=
                                            1;

                                        runPresent +=
                                            1;

                                    }

                                    else if (
                                        record.status ===
                                        "Absent"
                                    ) {

                                        absent +=
                                            1;

                                        runAbsent +=
                                            1;

                                    }

                                    else if (
                                        record.status ===
                                        "Late"
                                    ) {

                                        late +=
                                            1;

                                        runLate +=
                                            1;

                                    }

                                    else if (
                                        record.status ===
                                        "Excused"
                                    ) {

                                        excused +=
                                            1;

                                        runExcused +=
                                            1;

                                    }


                                    if (
                                        !participantMap.has(
                                            participantKey
                                        )
                                    ) {

                                        participantMap.set(
                                            participantKey,
                                            participant
                                        );

                                    }


                                    if (
                                        record.participantType ===
                                        "Beneficiary" &&
                                        record.beneficiary
                                    ) {

                                        const beneficiaryId =
                                            String(
                                                record.beneficiary._id
                                            );


                                        if (
                                            !runBeneficiaryMap.has(
                                                beneficiaryId
                                            )
                                        ) {

                                            runBeneficiaryMap.set(
                                                beneficiaryId,
                                                participant
                                            );

                                        }


                                        if (
                                            !beneficiaryMap.has(
                                                beneficiaryId
                                            )
                                        ) {

                                            beneficiaryMap.set(
                                                beneficiaryId,
                                                participant
                                            );

                                        }

                                    }

                                }
                            );


                            const runParticipants =
                                Array.from(
                                    runParticipantMap.values()
                                );


                            const runBeneficiaries =
                                Array.from(
                                    runBeneficiaryMap.values()
                                );


                            return {

                                id:
                                    activityRun._id,

                                runCode:
                                    activityRun.runCode,

                                name:
                                    activityRun.name,

                                startDate:
                                    activityRun.startDate,

                                endDate:
                                    activityRun.endDate,

                                region:
                                    activityRun.region,

                                zone:
                                    activityRun.zone,

                                woreda:
                                    activityRun.woreda,

                                location:
                                    activityRun.location,

                                targetGroup:
                                    activityRun.targetGroup,

                                status:
                                    activityRun.status,

                                notes:
                                    activityRun.notes,

                                trainer:
                                    activityRun.trainer
                                        ? {

                                            id:
                                                activityRun.trainer._id,

                                            name:
                                                buildFullName(
                                                    activityRun.trainer
                                                ),

                                            email:
                                                activityRun.trainer.email,

                                            phone:
                                                null

                                        }
                                        : null,

                                attendanceSessions:
                                    sessionDocuments.map(
                                        attendance => ({

                                            id:
                                                attendance._id,

                                            sessionTitle:
                                                attendance.sessionTitle,

                                            sessionNumber:
                                                attendance.sessionNumber,

                                            sessionDate:
                                                attendance.sessionDate

                                        })
                                    ),

                                totalAttendanceRecords:
                                    runRecords.length,

                                totalParticipants:
                                    runParticipants.length,

                                totalUniqueParticipants:
                                    runParticipants.length,

                                participants:
                                    runParticipants,

                                beneficiaryCount:
                                    runBeneficiaries.length,

                                beneficiaries:
                                    runBeneficiaries,

                                participantTypes:
                                    runParticipantTypeSummary,

                                attendance: {

                                    totalRecords:
                                        runRecords.length,

                                    present:
                                        runPresent,

                                    absent:
                                        runAbsent,

                                    late:
                                        runLate,

                                    excused:
                                        runExcused

                                }

                            };

                        }
                    );


                // =====================================
                // BENEFICIARIES
                // =====================================

                const beneficiaries =
                    Array.from(
                        beneficiaryMap.values()
                    );


                // =====================================
                // ALL PARTICIPANTS
                // =====================================

                const participants =
                    Array.from(
                        participantMap.values()
                    );


                // =====================================
                // PARTICIPANT TYPE TOTALS
                // =====================================

                const participantTypeCounts = {};


                PARTICIPANT_TYPES.forEach(
                    participantType => {

                        participantTypeCounts[
                            participantType
                        ] =
                            0;

                    }
                );


                activityRunDocuments.forEach(
                    activityRun => {

                        const runId =
                            String(
                                activityRun._id
                            );


                        const runRecords =
                            recordsByRun[
                                runId
                            ] || [];


                        runRecords.forEach(
                            record => {

                                if (
                                    participantTypeCounts[
                                        record.participantType
                                    ] ===
                                    undefined
                                ) {

                                    participantTypeCounts[
                                        record.participantType
                                    ] =
                                        0;

                                }


                                participantTypeCounts[
                                    record.participantType
                                ] +=
                                    1;

                            }
                        );

                    }
                );


                // =====================================
                // UNIQUE PARTICIPANT TYPE COUNTS
                // =====================================

                const uniqueParticipantTypeMaps = {};


                PARTICIPANT_TYPES.forEach(
                    participantType => {

                        uniqueParticipantTypeMaps[
                            participantType
                        ] =
                            new Map();

                    }
                );


                participants.forEach(
                    participant => {

                        let participantKey;


                        if (
                            participant.participantId
                        ) {

                            participantKey =
                                String(
                                    participant.participantId
                                );

                        }

                        else {

                            participantKey =
                                participant.participantType +
                                ":" +
                                (
                                    participant.participantName ||
                                    participant.attendanceRecordId
                                );

                        }


                        if (
                            uniqueParticipantTypeMaps[
                                participant.participantType
                            ]
                        ) {

                            uniqueParticipantTypeMaps[
                                participant.participantType
                            ].set(
                                participantKey,
                                participant
                            );

                        }

                    }
                );


                const uniqueParticipantTypeCounts = {};


                PARTICIPANT_TYPES.forEach(
                    participantType => {

                        uniqueParticipantTypeCounts[
                            participantType
                        ] =
                            uniqueParticipantTypeMaps[
                                participantType
                            ].size;

                    }
                );


                // =====================================
                // PARTICIPATION RATE
                // =====================================

                const uniqueBeneficiaries =
                    beneficiaryMap.size;


                const targetParticipantCount =
                    Number(
                        activity.targetParticipants || 0
                    );


                const participationRate =
                    targetParticipantCount > 0
                        ? Number(
                            (
                                (
                                    uniqueBeneficiaries /
                                    targetParticipantCount
                                ) *
                                100
                            ).toFixed(2)
                        )
                        : 0;


                // =====================================
                // EXTERNAL PARTICIPANTS
                // =====================================

                const externalParticipants =
                    participants.filter(
                        participant =>
                            EXTERNAL_PARTICIPANT_TYPES.includes(
                                participant.participantType
                            )
                    );


                return {

                    id:
                        activity._id,

                    activityCode:
                        activity.activityCode,

                    name:
                        activity.name,

                    activityType:
                        activity.activityType,

                    participantSource:
                        activity.participantSource,

                    targetGroups:
                        activity.targetGroups || [],

                    description:
                        activity.description,

                    activityDate:
                        activity.activityDate,

                    region:
                        activity.region,

                    zone:
                        activity.zone,

                    woreda:
                        activity.woreda,

                    location:
                        activity.location,

                    facilitator:
                        activity.facilitator,

                    targetParticipants:
                        targetParticipantCount,

                    status:
                        activity.status,

                    remarks:
                        activity.remarks,

                    program:
                        program,

                    project:
                        project,

                    activityRuns:
                        runRows,

                    totalActivityRuns:
                        runRows.length,

                    totalAttendanceSessions:
                        runRows.reduce(
                            (
                                total,
                                run
                            ) =>
                                total +
                                run.attendanceSessions.length,
                            0
                        ),

                    totalAttendanceRecords:
                        runRows.reduce(
                            (
                                total,
                                run
                            ) =>
                                total +
                                run.attendance.totalRecords,
                            0
                        ),

                    totalUniqueParticipants:
                        participants.length,

                    totalParticipants:
                        participants.length,

                    beneficiariesParticipated:
                        uniqueBeneficiaries,

                    staffParticipated:
                        uniqueParticipantTypeCounts.Staff,

                    boardParticipated:
                        uniqueParticipantTypeCounts.Board,

                    partnersParticipated:
                        uniqueParticipantTypeCounts.Partner,

                    governmentParticipants:
                        uniqueParticipantTypeCounts.Government,

                    communityParticipants:
                        uniqueParticipantTypeCounts.Community,

                    otherParticipants:
                        uniqueParticipantTypeCounts.Other,

                    externalParticipants:
                        externalParticipants,

                    participantTypeCounts:
                        participantTypeCounts,

                    uniqueParticipantTypeCounts:
                        uniqueParticipantTypeCounts,

                    participationRate:
                        participationRate,

                    attendance: {

                        totalRecords:
                            present +
                            absent +
                            late +
                            excused,

                        present:
                            present,

                        absent:
                            absent,

                        late:
                            late,

                        excused:
                            excused

                    },

                    participants:
                        participants,

                    beneficiaries:
                        beneficiaries

                };

            }
        );


    // =====================================================
    // SUMMARIES
    // =====================================================

    const statusSummary = {};

    const typeSummary = {};

    const participantSourceSummary = {};

    const programSummary = {};

    const projectSummary = {};

    const beneficiarySummary = {};

    const participantTypeSummary = {};

    const uniqueParticipantTypeSummary = {};


    PARTICIPANT_TYPES.forEach(
        participantType => {

            participantTypeSummary[
                participantType
            ] =
                0;

            uniqueParticipantTypeSummary[
                participantType
            ] =
                new Map();

        }
    );


    let targetParticipants =
        0;


    let totalAttendanceRecords =
        0;


    let totalPresent =
        0;


    let totalAbsent =
        0;


    let totalLate =
        0;


    let totalExcused =
        0;


    const globalParticipantMap =
        new Map();


    const globalBeneficiaryMap =
        new Map();


    const programParticipantMaps =
        new Map();


    const projectParticipantMaps =
        new Map();


    const programBeneficiaryMaps =
        new Map();


    const projectBeneficiaryMaps =
        new Map();


    rows.forEach(
        row => {

            // -----------------------------------------
            // STATUS
            // -----------------------------------------

            statusSummary[
                row.status
            ] =
                (
                    statusSummary[
                        row.status
                    ] ||
                    0
                ) + 1;


            // -----------------------------------------
            // ACTIVITY TYPE
            // -----------------------------------------

            typeSummary[
                row.activityType
            ] =
                (
                    typeSummary[
                        row.activityType
                    ] ||
                    0
                ) + 1;


            // -----------------------------------------
            // PARTICIPANT SOURCE
            // -----------------------------------------

            participantSourceSummary[
                row.participantSource
            ] =
                (
                    participantSourceSummary[
                        row.participantSource
                    ] ||
                    0
                ) + 1;


            // -----------------------------------------
            // TARGET PARTICIPANTS
            // -----------------------------------------

            targetParticipants +=
                Number(
                    row.targetParticipants || 0
                );


            // -----------------------------------------
            // ATTENDANCE
            // -----------------------------------------

            totalAttendanceRecords +=
                Number(
                    row.attendance.totalRecords || 0
                );


            totalPresent +=
                Number(
                    row.attendance.present || 0
                );


            totalAbsent +=
                Number(
                    row.attendance.absent || 0
                );


            totalLate +=
                Number(
                    row.attendance.late || 0
                );


            totalExcused +=
                Number(
                    row.attendance.excused || 0
                );


            // -----------------------------------------
            // PARTICIPANT TYPES
            // -----------------------------------------

            PARTICIPANT_TYPES.forEach(
                participantType => {

                    participantTypeSummary[
                        participantType
                    ] +=
                        Number(
                            row.participantTypeCounts[
                                participantType
                            ] || 0
                        );

                }
            );


            // -----------------------------------------
            // GLOBAL UNIQUE PARTICIPANTS
            // -----------------------------------------

            row.participants.forEach(
                participant => {

                    let participantKey;


                    if (
                        participant.participantId
                    ) {

                        participantKey =
                            participant.participantType +
                            ":" +
                            String(
                                participant.participantId
                            );

                    }

                    else {

                        participantKey =
                            participant.participantType +
                            ":" +
                            (
                                participant.participantName ||
                                participant.attendanceRecordId
                            );

                    }


                    if (
                        !globalParticipantMap.has(
                            participantKey
                        )
                    ) {

                        globalParticipantMap.set(
                            participantKey,
                            participant
                        );

                    }


                    if (
                        uniqueParticipantTypeSummary[
                            participant.participantType
                        ]
                    ) {

                        uniqueParticipantTypeSummary[
                            participant.participantType
                        ].set(
                            participantKey,
                            participant
                        );

                    }


                    // ---------------------------------
                    // GLOBAL UNIQUE BENEFICIARIES
                    // ---------------------------------

                    if (
                        participant.participantType ===
                        "Beneficiary" &&
                        participant.participantId
                    ) {

                        const beneficiaryId =
                            String(
                                participant.participantId
                            );


                        if (
                            !globalBeneficiaryMap.has(
                                beneficiaryId
                            )
                        ) {

                            globalBeneficiaryMap.set(
                                beneficiaryId,
                                participant
                            );

                        }

                    }

                }
            );


            // -----------------------------------------
            // PROGRAM
            // -----------------------------------------

            if (
                row.program
            ) {

                const programId =
                    String(
                        row.program.id
                    );


                if (
                    !programSummary[
                        programId
                    ]
                ) {

                    programSummary[
                        programId
                    ] = {

                        programId:
                            row.program.id,

                        programCode:
                            row.program.programCode,

                        program:
                            row.program.name,

                        status:
                            row.program.status,

                        activities:
                            0,

                        targetParticipants:
                            0,

                        beneficiariesParticipated:
                            0,

                        participants:
                            0,

                        attendanceRecords:
                            0,

                        present:
                            0,

                        absent:
                            0,

                        late:
                            0,

                        excused:
                            0

                    };

                }


                if (
                    !programParticipantMaps.has(
                        programId
                    )
                ) {

                    programParticipantMaps.set(
                        programId,
                        new Map()
                    );

                }


                if (
                    !programBeneficiaryMaps.has(
                        programId
                    )
                ) {

                    programBeneficiaryMaps.set(
                        programId,
                        new Map()
                    );

                }


                programSummary[
                    programId
                ].activities +=
                    1;


                programSummary[
                    programId
                ].targetParticipants +=
                    Number(
                        row.targetParticipants || 0
                    );


                programSummary[
                    programId
                ].attendanceRecords +=
                    Number(
                        row.attendance.totalRecords || 0
                    );


                programSummary[
                    programId
                ].present +=
                    Number(
                        row.attendance.present || 0
                    );


                programSummary[
                    programId
                ].absent +=
                    Number(
                        row.attendance.absent || 0
                    );


                programSummary[
                    programId
                ].late +=
                    Number(
                        row.attendance.late || 0
                    );


                programSummary[
                    programId
                ].excused +=
                    Number(
                        row.attendance.excused || 0
                    );


                const programParticipants =
                    programParticipantMaps.get(
                        programId
                    );


                row.participants.forEach(
                    participant => {

                        let participantKey;


                        if (
                            participant.participantId
                        ) {

                            participantKey =
                                participant.participantType +
                                ":" +
                                String(
                                    participant.participantId
                                );

                        }

                        else {

                            participantKey =
                                participant.participantType +
                                ":" +
                                (
                                    participant.participantName ||
                                    participant.attendanceRecordId
                                );

                        }


                        if (
                            !programParticipants.has(
                                participantKey
                            )
                        ) {

                            programParticipants.set(
                                participantKey,
                                participant
                            );

                        }

                    }
                );


                const programBeneficiaries =
                    programBeneficiaryMaps.get(
                        programId
                    );


                row.beneficiaries.forEach(
                    beneficiary => {

                        if (
                            !beneficiary.participantId
                        ) {

                            return;

                        }


                        const beneficiaryId =
                            String(
                                beneficiary.participantId
                            );


                        if (
                            !programBeneficiaries.has(
                                beneficiaryId
                            )
                        ) {

                            programBeneficiaries.set(
                                beneficiaryId,
                                beneficiary
                            );

                        }

                    }
                );

            }


            // -----------------------------------------
            // PROJECT
            // -----------------------------------------

            if (
                row.project
            ) {

                const projectId =
                    String(
                        row.project.id
                    );


                if (
                    !projectSummary[
                        projectId
                    ]
                ) {

                    projectSummary[
                        projectId
                    ] = {

                        projectId:
                            row.project.id,

                        projectCode:
                            row.project.projectCode,

                        project:
                            row.project.name,

                        status:
                            row.project.status,

                        programId:
                            row.program
                                ? row.program.id
                                : null,

                        programCode:
                            row.program
                                ? row.program.programCode
                                : null,

                        program:
                            row.program
                                ? row.program.name
                                : null,

                        activities:
                            0,

                        targetParticipants:
                            0,

                        beneficiariesParticipated:
                            0,

                        participants:
                            0,

                        attendanceRecords:
                            0,

                        present:
                            0,

                        absent:
                            0,

                        late:
                            0,

                        excused:
                            0

                    };

                }


                if (
                    !projectParticipantMaps.has(
                        projectId
                    )
                ) {

                    projectParticipantMaps.set(
                        projectId,
                        new Map()
                    );

                }


                if (
                    !projectBeneficiaryMaps.has(
                        projectId
                    )
                ) {

                    projectBeneficiaryMaps.set(
                        projectId,
                        new Map()
                    );

                }


                projectSummary[
                    projectId
                ].activities +=
                    1;


                projectSummary[
                    projectId
                ].targetParticipants +=
                    Number(
                        row.targetParticipants || 0
                    );


                projectSummary[
                    projectId
                ].attendanceRecords +=
                    Number(
                        row.attendance.totalRecords || 0
                    );


                projectSummary[
                    projectId
                ].present +=
                    Number(
                        row.attendance.present || 0
                    );


                projectSummary[
                    projectId
                ].absent +=
                    Number(
                        row.attendance.absent || 0
                    );


                projectSummary[
                    projectId
                ].late +=
                    Number(
                        row.attendance.late || 0
                    );


                projectSummary[
                    projectId
                ].excused +=
                    Number(
                        row.attendance.excused || 0
                    );


                const projectParticipants =
                    projectParticipantMaps.get(
                        projectId
                    );


                row.participants.forEach(
                    participant => {

                        let participantKey;


                        if (
                            participant.participantId
                        ) {

                            participantKey =
                                participant.participantType +
                                ":" +
                                String(
                                    participant.participantId
                                );

                        }

                        else {

                            participantKey =
                                participant.participantType +
                                ":" +
                                (
                                    participant.participantName ||
                                    participant.attendanceRecordId
                                );

                        }


                        if (
                            !projectParticipants.has(
                                participantKey
                            )
                        ) {

                            projectParticipants.set(
                                participantKey,
                                participant
                            );

                        }

                    }
                );


                const projectBeneficiaries =
                    projectBeneficiaryMaps.get(
                        projectId
                    );


                row.beneficiaries.forEach(
                    beneficiary => {

                        if (
                            !beneficiary.participantId
                        ) {

                            return;

                        }


                        const beneficiaryId =
                            String(
                                beneficiary.participantId
                            );


                        if (
                            !projectBeneficiaries.has(
                                beneficiaryId
                            )
                        ) {

                            projectBeneficiaries.set(
                                beneficiaryId,
                                beneficiary
                            );

                        }

                    }
                );

            }


            // -----------------------------------------
            // BENEFICIARY SUMMARY
            // -----------------------------------------

            row.beneficiaries.forEach(
                beneficiary => {

                    if (
                        !beneficiary.participantId
                    ) {

                        return;

                    }


                    const beneficiaryId =
                        String(
                            beneficiary.participantId
                        );


                    if (
                        !beneficiarySummary[
                            beneficiaryId
                        ]
                    ) {

                        beneficiarySummary[
                            beneficiaryId
                        ] = {

                            beneficiaryId:
                                beneficiary.participantId,

                            beneficiaryNumber:
                                beneficiary.participantNumber,

                            beneficiaryName:
                                beneficiary.participantName,

                            gender:
                                beneficiary.gender,

                            ageGroup:
                                beneficiary.ageGroup,

                            disabilityStatus:
                                beneficiary.disabilityStatus,

                            activities:
                                0

                        };

                    }


                    beneficiarySummary[
                        beneficiaryId
                    ].activities +=
                        1;

                }
            );

        }
    );


    // =====================================================
    // FINALIZE PROGRAM UNIQUE COUNTS
    // =====================================================

    Object.keys(
        programSummary
    ).forEach(
        programId => {

            const participantMap =
                programParticipantMaps.get(
                    programId
                );


            const beneficiaryMap =
                programBeneficiaryMaps.get(
                    programId
                );


            programSummary[
                programId
            ].participants =
                participantMap
                    ? participantMap.size
                    : 0;


            programSummary[
                programId
            ].beneficiariesParticipated =
                beneficiaryMap
                    ? beneficiaryMap.size
                    : 0;

        }
    );


    // =====================================================
    // FINALIZE PROJECT UNIQUE COUNTS
    // =====================================================

    Object.keys(
        projectSummary
    ).forEach(
        projectId => {

            const participantMap =
                projectParticipantMaps.get(
                    projectId
                );


            const beneficiaryMap =
                projectBeneficiaryMaps.get(
                    projectId
                );


            projectSummary[
                projectId
            ].participants =
                participantMap
                    ? participantMap.size
                    : 0;


            projectSummary[
                projectId
            ].beneficiariesParticipated =
                beneficiaryMap
                    ? beneficiaryMap.size
                    : 0;

        }
    );


    // =====================================================
    // UNIQUE PARTICIPANT TYPE SUMMARY
    // =====================================================

    const uniqueParticipantCounts = {};


    PARTICIPANT_TYPES.forEach(
        participantType => {

            uniqueParticipantCounts[
                participantType
            ] =
                uniqueParticipantTypeSummary[
                    participantType
                ].size;

        }
    );


    // =====================================================
    // PARTICIPANT TYPE CHART
    // =====================================================

    const participantsByType =
        PARTICIPANT_TYPES.map(
            participantType => ({

                participantType:
                    participantType,

                attendanceRecords:
                    participantTypeSummary[
                        participantType
                    ],

                uniqueParticipants:
                    uniqueParticipantCounts[
                        participantType
                    ]

            })
        );


    // =====================================================
    // RESPONSE
    // =====================================================

    return {

        report:
            "activityReport",

        reportTitle:
            "Activity Report",

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

        filters: {

            program:
                filters.program || null,

            project:
                filters.project || null,

            activity:
                filters.activity || null,

            activityRun:
                filters.activityRun || null,

            status:
                filters.status || null,

            activityType:
                filters.activityType || null,

            participantSource:
                filters.participantSource || null,

            ...getLocationFilterSummary(
                filters
            )

        },

        summary: {

            totalActivities:
                rows.length,

            totalTargetParticipants:
                targetParticipants,

            totalBeneficiariesParticipated:
                globalBeneficiaryMap.size,

            totalAttendanceRecords:
                totalAttendanceRecords,

            totalPresent:
                totalPresent,

            totalAbsent:
                totalAbsent,

            totalLate:
                totalLate,

            totalExcused:
                totalExcused,

            totalUniqueParticipants:
                globalParticipantMap.size,

            totalUniqueBeneficiaries:
                globalBeneficiaryMap.size,

            totalStaff:
                uniqueParticipantCounts.Staff,

            totalBoardMembers:
                uniqueParticipantCounts.Board,

            totalPartners:
                uniqueParticipantCounts.Partner,

            totalGovernmentParticipants:
                uniqueParticipantCounts.Government,

            totalCommunityParticipants:
                uniqueParticipantCounts.Community,

            totalOtherParticipants:
                uniqueParticipantCounts.Other,

            totalActivityRuns:
                activityRuns.length,

            totalAttendanceSessions:
                attendanceSessions.length,

            programsWithActivities:
                Object.keys(
                    programSummary
                ).length,

            projectsWithActivities:
                Object.keys(
                    projectSummary
                ).length,

            status:
                statusSummary,

            activityTypes:
                typeSummary,

            participantSources:
                participantSourceSummary,

            participantTypes:
                participantTypeSummary,

            uniqueParticipantTypes:
                uniqueParticipantCounts

        },

        charts: {

            activitiesByStatus:
                Object.entries(
                    statusSummary
                ).map(
                    (
                        [
                            status,
                            activities
                        ]
                    ) => ({

                        status:
                            status,

                        activities:
                            activities

                    })
                ),

            activitiesByType:
                Object.entries(
                    typeSummary
                ).map(
                    (
                        [
                            activityType,
                            activities
                        ]
                    ) => ({

                        activityType:
                            activityType,

                        activities:
                            activities

                    })
                ),

            activitiesByParticipantSource:
                Object.entries(
                    participantSourceSummary
                ).map(
                    (
                        [
                            participantSource,
                            activities
                        ]
                    ) => ({

                        participantSource:
                            participantSource,

                        activities:
                            activities

                    })
                ),

            participantsByType:
                participantsByType,

            activitiesByProgram:
                Object.values(
                    programSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        activities:
                            item.activities,

                        targetParticipants:
                            item.targetParticipants,

                        beneficiariesParticipated:
                            item.beneficiariesParticipated,

                        participants:
                            item.participants,

                        attendanceRecords:
                            item.attendanceRecords,

                        present:
                            item.present,

                        absent:
                            item.absent,

                        late:
                            item.late,

                        excused:
                            item.excused

                    })
                ),

            activitiesByProject:
                Object.values(
                    projectSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        projectId:
                            item.projectId,

                        projectCode:
                            item.projectCode,

                        project:
                            item.project,

                        activities:
                            item.activities,

                        targetParticipants:
                            item.targetParticipants,

                        beneficiariesParticipated:
                            item.beneficiariesParticipated,

                        participants:
                            item.participants,

                        attendanceRecords:
                            item.attendanceRecords,

                        present:
                            item.present,

                        absent:
                            item.absent,

                        late:
                            item.late,

                        excused:
                            item.excused

                    })
                ),

            beneficiariesByProgram:
                Object.values(
                    programSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        beneficiariesParticipated:
                            item.beneficiariesParticipated

                    })
                ),

            beneficiariesByProject:
                Object.values(
                    projectSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        projectId:
                            item.projectId,

                        projectCode:
                            item.projectCode,

                        project:
                            item.project,

                        beneficiariesParticipated:
                            item.beneficiariesParticipated

                    })
                ),

            participantsByProgram:
                Object.values(
                    programSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        participants:
                            item.participants

                    })
                ),

            participantsByProject:
                Object.values(
                    projectSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        projectId:
                            item.projectId,

                        projectCode:
                            item.projectCode,

                        project:
                            item.project,

                        participants:
                            item.participants

                    })
                ),

            targetParticipantsByProgram:
                Object.values(
                    programSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        targetParticipants:
                            item.targetParticipants

                    })
                ),

            targetParticipantsByProject:
                Object.values(
                    projectSummary
                ).map(
                    item => ({

                        programId:
                            item.programId,

                        programCode:
                            item.programCode,

                        program:
                            item.program,

                        projectId:
                            item.projectId,

                        projectCode:
                            item.projectCode,

                        project:
                            item.project,

                        targetParticipants:
                            item.targetParticipants

                    })
                )

        },

        details:
            rows,

        data:
            rows

    };

};


module.exports = {

    generate

};