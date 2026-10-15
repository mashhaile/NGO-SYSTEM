const mongoose = require("mongoose");

const Attendance = require("../../models/Attendance");
const AttendanceRecord = require("../../models/AttendanceRecord");
const Lookup = require("../../models/Lookup");


// =====================================================
// HELPERS
// =====================================================

const hasValue = (value) => {

    return (
        value !== undefined &&
        value !== null &&
        value !== ""
    );

};


// =====================================================
// LOOKUP DISPLAY VALUE
// =====================================================

const getLookupDisplayValue = (value) => {

    if (!hasValue(value)) {
        return null;
    }

    // Already a string / primitive
    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {

        return String(value);

    }

    // Populated lookup object
    if (typeof value === "object") {

        return (
            value.name ||
            value.label ||
            value.value ||
            value.displayName ||
            value.title ||
            value.code ||
            value.description ||
            (
                value._id
                    ? String(value._id)
                    : null
            )
        );

    }

    return String(value);

};


// =====================================================
// DATE FILTER
// =====================================================

const buildDateFilter = (filters = {}) => {

    let startDate = null;
    let endDate = null;


    // =================================================
    // EXPLICIT DATE RANGE
    // =================================================

    if (filters.startDate) {

        startDate =
            new Date(filters.startDate);

    }


    if (filters.endDate) {

        endDate =
            new Date(filters.endDate);

        // Include complete end date
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
    // REPORTING PERIOD
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
            )
                .trim()
                .toLowerCase();


        // =================================================
        // MONTHLY
        // =================================================

        if (
            period === "monthly" &&
            hasValue(filters.month)
        ) {

            const month =
                Number(filters.month) - 1;

            if (
                month >= 0 &&
                month <= 11
            ) {

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

        }


        // =================================================
        // QUARTERLY
        // =================================================

        if (
            period === "quarterly" &&
            hasValue(filters.quarter)
        ) {

            const quarter =
                Number(filters.quarter);

            if (
                quarter >= 1 &&
                quarter <= 4
            ) {

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

        }


        // =================================================
        // SEMI ANNUAL
        // =================================================

        if (
            [
                "semiannual",
                "semi-annual",
                "sixmonthly",
                "six-monthly"
            ].includes(period) &&
            hasValue(filters.half)
        ) {

            const half =
                Number(filters.half);


            // FIRST HALF

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


            // SECOND HALF

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


        // =================================================
        // ANNUAL
        // =================================================

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


    // =================================================
    // BUILD MONGODB FILTER
    // =================================================

    const filter = {};


    if (
        startDate ||
        endDate
    ) {

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
// CALCULATE AGE
// =====================================================

const calculateAge = (dateOfBirth) => {

    if (!dateOfBirth) {
        return null;
    }

    const dob =
        new Date(dateOfBirth);

    if (
        Number.isNaN(
            dob.getTime()
        )
    ) {

        return null;

    }

    const today =
        new Date();

    let age =
        today.getFullYear() -
        dob.getFullYear();

    const month =
        today.getMonth() -
        dob.getMonth();

    if (
        month < 0 ||
        (
            month === 0 &&
            today.getDate() < dob.getDate()
        )
    ) {

        age--;

    }

    return age >= 0
        ? age
        : null;

};


// =====================================================
// CALCULATE AGE GROUP
// =====================================================

const calculateAgeGroup = (dateOfBirth) => {

    const age =
        calculateAge(
            dateOfBirth
        );

    if (age === null) {
        return null;
    }


    if (age <= 5) {
        return "0-5";
    }

    if (age <= 12) {
        return "6-12";
    }

    if (age <= 17) {
        return "13-17";
    }

    if (age <= 24) {
        return "18-24";
    }

    if (age <= 59) {
        return "25-59";
    }

    return "60+";

};


// =====================================================
// GET PARTICIPANT NAME
// =====================================================

const getParticipantName = (record) => {

    const participantType =
        String(
            record.participantType || ""
        )
            .trim()
            .toLowerCase();


    // =================================================
    // BENEFICIARY
    // =================================================

    if (
        participantType === "beneficiary" &&
        record.beneficiary
    ) {

        return [
            record.beneficiary.firstName,
            record.beneficiary.middleName,
            record.beneficiary.lastName
        ]
            .filter(Boolean)
            .join(" ");

    }


    // =================================================
    // STAFF
    // =================================================

    if (
        participantType === "staff" &&
        record.staff
    ) {

        return [
            record.staff.firstName,
            record.staff.middleName,
            record.staff.lastName
        ]
            .filter(Boolean)
            .join(" ");

    }


    // =================================================
    // EXTERNAL
    // =================================================

    if (
        record.externalParticipant &&
        hasValue(
            record.externalParticipant.name
        )
    ) {

        return record.externalParticipant.name;

    }


    // =================================================
    // FALLBACK
    // =================================================

    if (
        hasValue(
            record.participantName
        )
    ) {

        return record.participantName;

    }


    return null;

};


// =====================================================
// GET PARTICIPANT GENDER
// =====================================================

const getParticipantGender = (record) => {

    const participantType =
        String(
            record.participantType || ""
        )
            .trim()
            .toLowerCase();


    // =================================================
    // BENEFICIARY
    // =================================================

    if (
        participantType === "beneficiary" &&
        record.beneficiary
    ) {

        if (
            hasValue(
                record.beneficiary.gender
            )
        ) {

            return getLookupDisplayValue(
                record.beneficiary.gender
            );

        }

    }


    // =================================================
    // STAFF
    // =================================================

    if (
        participantType === "staff" &&
        record.staff
    ) {

        if (
            hasValue(
                record.staff.gender
            )
        ) {

            return getLookupDisplayValue(
                record.staff.gender
            );

        }

    }


    // =================================================
    // EXTERNAL PARTICIPANT
    // =================================================

    if (
        record.externalParticipant &&
        hasValue(
            record.externalParticipant.gender
        )
    ) {

        return getLookupDisplayValue(
            record.externalParticipant.gender
        );

    }


    // =================================================
    // ATTENDANCE RECORD
    // =================================================

    if (
        hasValue(
            record.gender
        )
    ) {

        return getLookupDisplayValue(
            record.gender
        );

    }


    return null;

};


// =====================================================
// GET PARTICIPANT AGE GROUP
// =====================================================

const getParticipantAgeGroup = (record) => {

    const participantType =
        String(
            record.participantType || ""
        )
            .trim()
            .toLowerCase();


    // =================================================
    // BENEFICIARY
    // =================================================

    if (
        participantType === "beneficiary" &&
        record.beneficiary
    ) {

        const calculated =
            calculateAgeGroup(
                record.beneficiary.dateOfBirth
            );

        if (calculated) {
            return calculated;
        }

    }


    // =================================================
    // STAFF
    // =================================================

    if (
        participantType === "staff" &&
        record.staff
    ) {

        const calculated =
            calculateAgeGroup(
                record.staff.dateOfBirth
            );

        if (calculated) {
            return calculated;
        }

    }


    // =================================================
    // ATTENDANCE RECORD FALLBACK
    // =================================================

    if (
        hasValue(
            record.ageGroup
        )
    ) {

        return record.ageGroup;

    }


    return null;

};


// =====================================================
// GET PARTICIPANT DISABILITY
// =====================================================

const getParticipantDisability = (record) => {

    const participantType =
        String(
            record.participantType || ""
        )
            .trim()
            .toLowerCase();


    // =================================================
    // BENEFICIARY
    // =================================================

    if (
        participantType === "beneficiary" &&
        record.beneficiary
    ) {

        if (
            hasValue(
                record.beneficiary.disabilityStatus
            )
        ) {

            return Boolean(
                record.beneficiary.disabilityStatus
            );

        }


        if (
            hasValue(
                record.beneficiary.disability
            )
        ) {

            return Boolean(
                record.beneficiary.disability
            );

        }


        if (
            hasValue(
                record.beneficiary.hasDisability
            )
        ) {

            return Boolean(
                record.beneficiary.hasDisability
            );

        }

    }


    // =================================================
    // STAFF
    // =================================================

    if (
        participantType === "staff" &&
        record.staff
    ) {

        if (
            hasValue(
                record.staff.disabilityStatus
            )
        ) {

            return Boolean(
                record.staff.disabilityStatus
            );

        }


        if (
            hasValue(
                record.staff.disability
            )
        ) {

            return Boolean(
                record.staff.disability
            );

        }


        if (
            hasValue(
                record.staff.hasDisability
            )
        ) {

            return Boolean(
                record.staff.hasDisability
            );

        }

    }


    // =================================================
    // ATTENDANCE RECORD
    // =================================================

    if (
        hasValue(
            record.disabilityStatus
        )
    ) {

        return Boolean(
            record.disabilityStatus
        );

    }


    if (
        hasValue(
            record.disability
        )
    ) {

        return Boolean(
            record.disability
        );

    }


    if (
        hasValue(
            record.hasDisability
        )
    ) {

        return Boolean(
            record.hasDisability
        );

    }


    return false;

};


// =====================================================
// RESOLVE GENDER LOOKUPS
// =====================================================
//
// Gender is stored as a Lookup ObjectId in your data.
// We resolve the IDs separately instead of trying to
// populate unknown nested schema paths.
//
// This avoids BoardMember / external participant
// population problems.
// =====================================================

const resolveGenderLookups = async (records) => {

    const genderIds = [];


    records.forEach(
        record => {

            const sources = [
                record.gender,

                record.beneficiary
                    ? record.beneficiary.gender
                    : null,

                record.staff
                    ? record.staff.gender
                    : null,

                record.externalParticipant
                    ? record.externalParticipant.gender
                    : null
            ];


            sources.forEach(
                value => {

                    if (
                        value &&
                        typeof value === "object" &&
                        value._id
                    ) {

                        if (
                            mongoose.Types.ObjectId.isValid(
                                value._id
                            )
                        ) {

                            genderIds.push(
                                String(value._id)
                            );

                        }

                    }
                    else if (
                        typeof value === "string" &&
                        mongoose.Types.ObjectId.isValid(value)
                    ) {

                        genderIds.push(
                            String(value)
                        );

                    }

                }
            );

        }
    );


    const uniqueIds =
        [
            ...new Set(
                genderIds
            )
        ];


    if (!uniqueIds.length) {
        return new Map();
    }


    const lookups =
        await Lookup.find({
            _id: {
                $in:
                    uniqueIds
            }
        }).lean();


    const lookupMap =
        new Map();


    lookups.forEach(
        lookup => {

            const id =
                String(
                    lookup._id
                );

            lookupMap.set(
                id,
                getLookupDisplayValue(
                    lookup
                )
            );

        }
    );


    return lookupMap;

};


// =====================================================
// RESOLVE GENDER VALUE
// =====================================================

const resolveGenderValue = (
    value,
    genderLookupMap
) => {

    if (!hasValue(value)) {
        return null;
    }


    // Populated object
    if (
        typeof value === "object" &&
        value._id
    ) {

        const id =
            String(
                value._id
            );

        return (
            genderLookupMap.get(id) ||
            getLookupDisplayValue(value)
        );

    }


    // ObjectId / string ID
    if (
        typeof value === "string" &&
        mongoose.Types.ObjectId.isValid(value)
    ) {

        return (
            genderLookupMap.get(value) ||
            value
        );

    }


    return getLookupDisplayValue(
        value
    );

};


// =====================================================
// GENERATE ATTENDANCE REPORT
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
    // ATTENDANCE SESSION QUERY
    // =================================================

    const attendanceQuery = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // PROGRAM
    // =================================================

    if (filters.program) {

        attendanceQuery.program =
            filters.program;

    }


    // =================================================
    // PROJECT
    // =================================================

    if (filters.project) {

        attendanceQuery.project =
            filters.project;

    }


    // =================================================
    // ACTIVITY RUN
    // =================================================

    if (filters.activityRun) {

        attendanceQuery.activityRun =
            filters.activityRun;

    }


    // =================================================
    // DATE
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

        attendanceQuery.sessionDate =
            dateFilter;

    }


    // =================================================
    // GET ATTENDANCE SESSIONS
    // =================================================

    const sessions =
        await Attendance.find(
            attendanceQuery
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
            "activityRun",
            "runCode name startDate endDate status"
        )

        .sort({
            sessionDate: -1
        });


    // =================================================
    // SESSION IDS
    // =================================================

    const sessionIds =
        sessions.map(
            session =>
                session._id
        );


    // =================================================
    // ATTENDANCE RECORDS
    // =================================================

    let records = [];


    if (
        sessionIds.length
    ) {

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


        // =================================================
        // PARTICIPANT TYPE
        // =================================================

        if (
            filters.participantType
        ) {

            recordQuery.participantType =
                filters.participantType;

        }


        // =================================================
        // ATTENDANCE STATUS
        // =================================================

        if (
            filters.status
        ) {

            recordQuery.status =
                filters.status;

        }


        // =================================================
        // GET RECORDS
        // =================================================

        records =
            await AttendanceRecord.find(
                recordQuery
            )

            // =============================================
            // BENEFICIARY
            // =============================================

            .populate(
                "beneficiary",
                [
                    "beneficiaryNumber",
                    "firstName",
                    "middleName",
                    "lastName",
                    "gender",
                    "dateOfBirth",
                    "disabilityStatus",
                    "disability",
                    "hasDisability"
                ].join(" ")
            )

            // =============================================
            // STAFF
            // =============================================

            .populate(
                "staff",
                [
                    "firstName",
                    "middleName",
                    "lastName",
                    "email",
                    "gender",
                    "dateOfBirth",
                    "disabilityStatus",
                    "disability",
                    "hasDisability"
                ].join(" ")
            );

    }


    // =================================================
    // RESOLVE GENDER LOOKUPS
    // =================================================

    const genderLookupMap =
        await resolveGenderLookups(
            records
        );


    // =================================================
    // RESOLVE DEMOGRAPHICS
    // =================================================

    records =
        records.map(
            record => {

                const object =
                    record.toObject();


                const gender =
                    getParticipantGender(
                        object
                    );


                const resolvedGender =
                    (() => {

                        const participantType =
                            String(
                                object.participantType || ""
                            )
                                .trim()
                                .toLowerCase();


                        if (
                            participantType === "beneficiary" &&
                            object.beneficiary
                        ) {

                            return resolveGenderValue(
                                object.beneficiary.gender,
                                genderLookupMap
                            );

                        }


                        if (
                            participantType === "staff" &&
                            object.staff
                        ) {

                            return resolveGenderValue(
                                object.staff.gender,
                                genderLookupMap
                            );

                        }


                        if (
                            object.externalParticipant &&
                            hasValue(
                                object.externalParticipant.gender
                            )
                        ) {

                            return resolveGenderValue(
                                object.externalParticipant.gender,
                                genderLookupMap
                            );

                        }


                        return resolveGenderValue(
                            object.gender,
                            genderLookupMap
                        );

                    })();


                const ageGroup =
                    getParticipantAgeGroup(
                        object
                    );


                const disabilityStatus =
                    getParticipantDisability(
                        object
                    );


                return {

                    ...object,

                    participantName:
                        getParticipantName(
                            object
                        ),

                    resolvedGender:
                        resolvedGender ||
                        gender ||
                        null,

                    resolvedAgeGroup:
                        ageGroup,

                    resolvedDisabilityStatus:
                        disabilityStatus

                };

            }
        );


    // =================================================
    // APPLY GENDER FILTER
    // =================================================

    if (
        hasValue(
            filters.gender
        )
    ) {

        const requestedGender =
            String(
                filters.gender
            )
                .trim()
                .toLowerCase();


        records =
            records.filter(
                record => {

                    const gender =
                        String(
                            record.resolvedGender || ""
                        )
                            .trim()
                            .toLowerCase();


                    return (
                        gender ===
                        requestedGender
                    );

                }
            );

    }


    // =================================================
    // APPLY AGE GROUP FILTER
    // =================================================

    if (
        hasValue(
            filters.ageGroup
        )
    ) {

        const requestedAgeGroup =
            String(
                filters.ageGroup
            )
                .trim()
                .toLowerCase();


        records =
            records.filter(
                record => {

                    const ageGroup =
                        String(
                            record.resolvedAgeGroup || ""
                        )
                            .trim()
                            .toLowerCase();


                    return (
                        ageGroup ===
                        requestedAgeGroup
                    );

                }
            );

    }


    // =================================================
    // APPLY DISABILITY FILTER
    // =================================================

    if (
        hasValue(
            filters.disability
        )
    ) {

        const disabilityFilter =
            String(
                filters.disability
            )
                .trim()
                .toLowerCase();


        let requestedValue = null;


        if (
            [
                "true",
                "1",
                "yes",
                "disabled"
            ].includes(
                disabilityFilter
            )
        ) {

            requestedValue = true;

        }


        if (
            [
                "false",
                "0",
                "no",
                "notdisabled",
                "not-disabled",
                "non-disabled"
            ].includes(
                disabilityFilter
            )
        ) {

            requestedValue = false;

        }


        if (
            requestedValue !== null
        ) {

            records =
                records.filter(
                    record =>
                        record.resolvedDisabilityStatus ===
                        requestedValue
                );

        }

    }


    // =================================================
    // BUILD SESSION ROWS
    // =================================================

    const rows =
        sessions.map(
            session => {

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


                // =================================================
                // STATUS COUNTS
                // =================================================

                const present =
                    sessionRecords.filter(
                        record =>
                            String(
                                record.status
                            ).toLowerCase() ===
                            "present"
                    ).length;


                const absent =
                    sessionRecords.filter(
                        record =>
                            String(
                                record.status
                            ).toLowerCase() ===
                            "absent"
                    ).length;


                const late =
                    sessionRecords.filter(
                        record =>
                            String(
                                record.status
                            ).toLowerCase() ===
                            "late"
                    ).length;


                const excused =
                    sessionRecords.filter(
                        record =>
                            String(
                                record.status
                            ).toLowerCase() ===
                            "excused"
                    ).length;


                // =================================================
                // SESSION ROW
                // =================================================

                return {

                    id:
                        session._id,

                    sessionTitle:
                        session.sessionTitle,

                    sessionNumber:
                        session.sessionNumber,

                    sessionDate:
                        session.sessionDate,

                    notes:
                        session.notes || null,


                    // =================================================
                    // PROGRAM
                    // =================================================

                    program:
                        session.program
                            ? {

                                id:
                                    session.program._id,

                                programCode:
                                    session.program.programCode,

                                name:
                                    session.program.name,

                                status:
                                    session.program.status

                            }
                            : null,


                    // =================================================
                    // PROJECT
                    // =================================================

                    project:
                        session.project
                            ? {

                                id:
                                    session.project._id,

                                projectCode:
                                    session.project.projectCode,

                                name:
                                    session.project.name,

                                status:
                                    session.project.status

                            }
                            : null,


                    // =================================================
                    // ACTIVITY RUN
                    // =================================================

                    activityRun:
                        session.activityRun
                            ? {

                                id:
                                    session.activityRun._id,

                                runCode:
                                    session.activityRun.runCode,

                                name:
                                    session.activityRun.name,

                                startDate:
                                    session.activityRun.startDate,

                                endDate:
                                    session.activityRun.endDate,

                                status:
                                    session.activityRun.status

                            }
                            : null,


                    // =================================================
                    // SUMMARY
                    // =================================================

                    summary: {

                        totalRecords:
                            sessionRecords.length,

                        present,

                        absent,

                        late,

                        excused

                    },


                    // =================================================
                    // RECORDS
                    // =================================================

                    records:
                        sessionRecords.map(
                            record => {

                                const beneficiary =
                                    record.beneficiary;


                                const staff =
                                    record.staff;


                                const external =
                                    record.externalParticipant;


                                return {

                                    id:
                                        record._id,


                                    participantType:
                                        record.participantType,


                                    participantName:
                                        record.participantName,


                                    gender:
                                        record.resolvedGender,


                                    ageGroup:
                                        record.resolvedAgeGroup,


                                    disabilityStatus:
                                        record.resolvedDisabilityStatus,


                                    status:
                                        record.status,


                                    checkInTime:
                                        record.checkInTime,


                                    checkOutTime:
                                        record.checkOutTime,


                                    location:
                                        record.location,


                                    notes:
                                        record.notes,


                                    // =================================
                                    // BENEFICIARY
                                    // =================================

                                    beneficiary:
                                        beneficiary
                                            ? {

                                                id:
                                                    beneficiary._id,

                                                beneficiaryNumber:
                                                    beneficiary
                                                        .beneficiaryNumber,

                                                name:
                                                    [
                                                        beneficiary.firstName,
                                                        beneficiary.middleName,
                                                        beneficiary.lastName
                                                    ]
                                                        .filter(Boolean)
                                                        .join(" "),

                                                gender:
                                                    resolveGenderValue(
                                                        beneficiary.gender,
                                                        genderLookupMap
                                                    ),

                                                dateOfBirth:
                                                    beneficiary.dateOfBirth,

                                                age:
                                                    calculateAge(
                                                        beneficiary.dateOfBirth
                                                    ),

                                                ageGroup:
                                                    calculateAgeGroup(
                                                        beneficiary.dateOfBirth
                                                    ),

                                                disabilityStatus:
                                                    getParticipantDisability(
                                                        {
                                                            participantType:
                                                                "Beneficiary",

                                                            beneficiary
                                                        }
                                                    )

                                            }
                                            : null,


                                    // =================================
                                    // STAFF
                                    // =================================

                                    staff:
                                        staff
                                            ? {

                                                id:
                                                    staff._id,

                                                name:
                                                    [
                                                        staff.firstName,
                                                        staff.middleName,
                                                        staff.lastName
                                                    ]
                                                        .filter(Boolean)
                                                        .join(" "),

                                                email:
                                                    staff.email,

                                                gender:
                                                    resolveGenderValue(
                                                        staff.gender,
                                                        genderLookupMap
                                                    ),

                                                dateOfBirth:
                                                    staff.dateOfBirth,

                                                age:
                                                    calculateAge(
                                                        staff.dateOfBirth
                                                    ),

                                                ageGroup:
                                                    calculateAgeGroup(
                                                        staff.dateOfBirth
                                                    ),

                                                disabilityStatus:
                                                    getParticipantDisability(
                                                        {
                                                            participantType:
                                                                "Staff",

                                                            staff
                                                        }
                                                    )

                                            }
                                            : null,


                                    // =================================
                                    // EXTERNAL PARTICIPANT
                                    // =================================

                                    externalParticipant:
                                        external &&
                                        Object.keys(
                                            external
                                        ).length
                                            ? {

                                                name:
                                                    external.name,

                                                gender:
                                                    resolveGenderValue(
                                                        external.gender,
                                                        genderLookupMap
                                                    ),

                                                organizationName:
                                                    external.organizationName,

                                                position:
                                                    external.position,

                                                phone:
                                                    external.phone,

                                                email:
                                                    external.email

                                            }
                                            : null

                                };

                            }
                        )

                };

            }
        );


    // =====================================================
    // GLOBAL TOTALS
    // =====================================================

    let totalRecords = 0;
    let totalPresent = 0;
    let totalAbsent = 0;
    let totalLate = 0;
    let totalExcused = 0;


    rows.forEach(
        row => {

            totalRecords +=
                row.summary.totalRecords;

            totalPresent +=
                row.summary.present;

            totalAbsent +=
                row.summary.absent;

            totalLate +=
                row.summary.late;

            totalExcused +=
                row.summary.excused;

        }
    );


    // =====================================================
    // ATTENDANCE RATE
    // =====================================================

    const attendanceRate =
        totalRecords > 0

            ? Number(
                (
                    (
                        totalPresent +
                        totalLate
                    ) /
                    totalRecords *
                    100
                ).toFixed(2)
            )

            : 0;


    // =====================================================
    // PARTICIPANT TYPE BREAKDOWN
    // =====================================================

    const participantTypeMap =
        new Map();


    records.forEach(
        record => {

            const type =
                record.participantType ||
                "Unknown";


            if (
                !participantTypeMap.has(type)
            ) {

                participantTypeMap.set(
                    type,
                    {

                        participantType:
                            type,

                        total:
                            0,

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


            const item =
                participantTypeMap.get(
                    type
                );


            item.total += 1;


            const status =
                String(
                    record.status || ""
                )
                    .trim()
                    .toLowerCase();


            if (status === "present") {
                item.present += 1;
            }

            if (status === "absent") {
                item.absent += 1;
            }

            if (status === "late") {
                item.late += 1;
            }

            if (status === "excused") {
                item.excused += 1;
            }

        }
    );


    const participantTypes =
        Array.from(
            participantTypeMap.values()
        );


    // =====================================================
    // GENDER BREAKDOWN
    // =====================================================

    const genderMap =
        new Map();


    records.forEach(
        record => {

            const gender =
                record.resolvedGender ||
                "Unknown";


            if (
                !genderMap.has(gender)
            ) {

                genderMap.set(
                    gender,
                    {

                        gender,

                        total:
                            0

                    }
                );

            }


            genderMap.get(
                gender
            ).total += 1;

        }
    );


    const genders =
        Array.from(
            genderMap.values()
        );


    // =====================================================
    // AGE GROUP BREAKDOWN
    // =====================================================

    const ageGroupMap =
        new Map();


    records.forEach(
        record => {

            const ageGroup =
                record.resolvedAgeGroup ||
                "Unknown";


            if (
                !ageGroupMap.has(
                    ageGroup
                )
            ) {

                ageGroupMap.set(
                    ageGroup,
                    {

                        ageGroup,

                        total:
                            0

                    }
                );

            }


            ageGroupMap.get(
                ageGroup
            ).total += 1;

        }
    );


    const ageGroups =
        Array.from(
            ageGroupMap.values()
        );


    // =====================================================
    // DISABILITY BREAKDOWN
    // =====================================================

    const disabilityMap = {

        disabled:
            0,

        notDisabled:
            0

    };


    records.forEach(
        record => {

            if (
                record.resolvedDisabilityStatus
            ) {

                disabilityMap.disabled += 1;

            }
            else {

                disabilityMap.notDisabled += 1;

            }

        }
    );


    // =====================================================
    // RETURN REPORT
    // =====================================================

    return {

        report:
            "attendanceReport",

        reportTitle:
            "Attendance Report",

        generatedAt:
            new Date(),


        // =================================================
        // PERIOD
        // =================================================

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


        // =================================================
        // FILTERS
        // =================================================

        filters: {

            program:
                filters.program ||
                null,

            project:
                filters.project ||
                null,

            activityRun:
                filters.activityRun ||
                null,

            participantType:
                filters.participantType ||
                null,

            status:
                filters.status ||
                null,

            gender:
                filters.gender ||
                null,

            ageGroup:
                filters.ageGroup ||
                null,

            disability:
                filters.disability !== undefined
                    ? filters.disability
                    : null

        },


        // =================================================
        // SUMMARY
        // =================================================

        summary: {

            totalSessions:
                rows.length,

            totalRecords,

            present:
                totalPresent,

            absent:
                totalAbsent,

            late:
                totalLate,

            excused:
                totalExcused,

            attendanceRate

        },


        // =================================================
        // BREAKDOWNS
        // =================================================

        participantTypes,

        genders,

        ageGroups,

        disability: {

            disabled:
                disabilityMap.disabled,

            notDisabled:
                disabilityMap.notDisabled

        },


        // =================================================
        // SESSION DATA
        // =================================================

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