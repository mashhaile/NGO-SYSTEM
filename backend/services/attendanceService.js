const Attendance = require("../models/Attendance");
const AttendanceRecord = require("../models/AttendanceRecord");
const ActivityRun = require("../models/ActivityRun");

// ==========================================
// CREATE ATTENDANCE SESSION
// ==========================================

const createAttendance = async (
    data,
    organizationId,
    userId
) => {

    const activityRun = await ActivityRun.findOne({
        _id: data.activityRun,
        organization: organizationId,
        isDeleted: false
    });

    if (!activityRun) {
        throw new Error("Activity run not found.");
    }

    const attendance = await Attendance.create({

        organization: organizationId,

        activityRun: activityRun._id,

        project: activityRun.project,

        program: activityRun.program,

        sessionTitle: data.sessionTitle,

        sessionNumber: data.sessionNumber || null,

        sessionDate: data.sessionDate,

        notes: data.notes || null,

        createdBy: userId

    });

    return await Attendance.findById(attendance._id)

        .populate(
            "activityRun",
            "runCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        );

};


// ==========================================
// GET ALL ATTENDANCE SESSIONS
// ==========================================

const getAttendances = async (
    organizationId,
    query = {}
) => {

    const {
        search = "",
        activityRun,
        project,
        program,
        page = 1,
        limit = 10
    } = query;

    const filter = {

        organization: organizationId,

        isDeleted: false

    };

    if (activityRun) {

        filter.activityRun = activityRun;

    }

    if (project) {

        filter.project = project;

    }

    if (program) {

        filter.program = program;

    }

    if (search) {

        filter.$or = [

            {
                sessionTitle: {
                    $regex: search,
                    $options: "i"
                }
            }

        ];

    }

    const skip =
        (Number(page) - 1) *
        Number(limit);

    const [
        data,
        total
    ] = await Promise.all([

        Attendance.find(filter)

            .populate(
                "activityRun",
                "runCode name"
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
                sessionDate: -1,
                createdAt: -1
            })

            .skip(skip)

            .limit(Number(limit)),

        Attendance.countDocuments(filter)

    ]);

    return {

        data,

        pagination: {

            total,

            page: Number(page),

            limit: Number(limit),

            pages:
                Math.ceil(
                    total /
                    Number(limit)
                )

        }

    };

};


// ==========================================
// GET SINGLE ATTENDANCE
// ==========================================

const getAttendanceById = async (
    id,
    organizationId
) => {

    return Attendance.findOne({

        _id: id,

        organization: organizationId,

        isDeleted: false

    })

        .populate(
            "activityRun",
            "runCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        );

};


// ==========================================
// SAVE ATTENDANCE RECORDS
// ==========================================

const saveAttendanceRecords = async (
    attendanceId,
    records,
    organizationId,
    userId
) => {

    const attendance =
        await Attendance.findOne({

            _id: attendanceId,

            organization: organizationId,

            isDeleted: false

        });

    if (!attendance) {

        throw new Error(
            "Attendance session not found."
        );

    }

    // ==========================================
    // Remove existing records
    // ==========================================

    await AttendanceRecord.deleteMany({

        attendance: attendanceId,

        organization: organizationId

    });

    // ==========================================
    // Prepare records
    // ==========================================

    const preparedRecords =
        records.map(
            (item) => {

                const participantType =
                    item.participantType;

                const record = {

                    organization:
                        organizationId,

                    attendance:
                        attendanceId,

                    activityRun:
                        attendance.activityRun,

                    project:
                        attendance.project,

                    program:
                        attendance.program,

                    participantType:
                        participantType,

                    beneficiary:
                        participantType ===
                        "Beneficiary"
                            ? item.beneficiary || null
                            : null,

                    staff:
                        participantType ===
                        "Staff"
                            ? item.staff || null
                            : null,

                    externalParticipant:
                        [
                            "Board",
                            "Partner",
                            "Government",
                            "Community",
                            "Other"
                        ].includes(
                            participantType
                        )
                            ? item.externalParticipant || null
                            : null,

                    gender:
                        item.gender || null,

                    ageGroup:
                        item.ageGroup || null,

                    location:
                        item.location || null,

                    disabilityStatus:
                        item.disabilityStatus ||
                        false,

                    status:
                        item.status ||
                        "Present",

                    notes:
                        item.notes || null,

                    createdBy:
                        userId

                };

                return record;

            }
        );

    // ==========================================
    // Empty records
    // ==========================================

    if (
        preparedRecords.length === 0
    ) {

        return [];

    }

    // ==========================================
    // Save records
    // ==========================================

    return await AttendanceRecord.insertMany(
        preparedRecords
    );

};


// ==========================================
// GET ATTENDANCE RECORDS
// ==========================================

const getAttendanceRecords = async (
    attendanceId,
    organizationId
) => {

    const records =
        await AttendanceRecord.find({

            attendance: attendanceId,

            organization: organizationId,

            isDeleted: false

        })
            .populate(
                "beneficiary",
                "beneficiaryNumber firstName middleName lastName gender"
            )
            .populate(
                "staff",
                "name email role"
            )
            .sort({
                createdAt: 1
            });

    return records;

};


// ==========================================
// UPDATE ATTENDANCE SESSION
// ==========================================

const updateAttendance = async (
    id,
    data,
    organizationId,
    userId
) => {

    return Attendance.findOneAndUpdate(

        {

            _id: id,

            organization: organizationId,

            isDeleted: false

        },

        {

            sessionTitle:
                data.sessionTitle,

            sessionNumber:
                data.sessionNumber ||
                null,

            sessionDate:
                data.sessionDate,

            notes:
                data.notes ||
                null,

            updatedBy:
                userId

        },

        {

            new: true,

            runValidators: true

        }

    )

        .populate(
            "activityRun",
            "runCode name"
        )

        .populate(
            "project",
            "projectCode name"
        )

        .populate(
            "program",
            "programCode name"
        );

};


// ==========================================
// DELETE ATTENDANCE SESSION
// ==========================================

const deleteAttendance = async (
    id,
    organizationId,
    userId
) => {

    await AttendanceRecord.updateMany(

        {

            attendance: id,

            organization: organizationId,

            isDeleted: false

        },

        {

            isDeleted: true,

            deletedAt: new Date(),

            deletedBy: userId

        }

    );

    return Attendance.findOneAndUpdate(

        {

            _id: id,

            organization: organizationId,

            isDeleted: false

        },

        {

            isDeleted: true,

            deletedAt: new Date(),

            deletedBy: userId

        },

        {

            new: true

        }

    );

};


module.exports = {

    createAttendance,

    getAttendances,

    getAttendanceById,

    saveAttendanceRecords,

    getAttendanceRecords,

    updateAttendance,

    deleteAttendance

};
