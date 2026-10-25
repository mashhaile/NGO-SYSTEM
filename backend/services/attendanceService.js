const escapeRegex = require("../utils/escapeRegex");
const Attendance = require("../models/Attendance");
const ApiError = require("../utils/apiError");
const { runInTransaction } = require("../utils/transaction");
const AttendanceRecord = require("../models/AttendanceRecord");
const ActivityRun = require("../models/ActivityRun");
const Beneficiary = require("../models/Beneficiary");

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
                    $regex: escapeRegex(search),
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
// ATTENDANCE LOCATION RESOLVER
// ==========================================
//
// Builds the location snapshot for attendance
// records, in order of preference:
//
// 1. Beneficiary: registered location
// 2. External: location entered on the sheet
// 3. Otherwise: activity run location
//
// Site is always the activity run venue.
//
// Also used by scripts/backfillAttendanceLocations.js
//
// ==========================================

const createAttendanceLocationResolver = async ({
    organizationId,
    activityRunId,
    participants = []
}) => {

    const LOCATION_FIELDS = [
        "region",
        "regionCode",
        "zone",
        "zoneCode",
        "woreda",
        "woredaCode",
        "kebele"
    ];

    const pickLocation = (source) => {

        if (!source) {
            return null;
        }

        const location = {};

        LOCATION_FIELDS.forEach(field => {
            if (source[field]) {
                location[field] =
                    source[field];
            }
        });

        return Object.keys(location).length
            ? location
            : null;

    };

    const hasLocation = (location) =>
        Boolean(
            location &&
            Object.values(location)
                .some(Boolean)
        );


    const beneficiaryIds =
        participants
            .filter(
                item =>
                    item.participantType ===
                        "Beneficiary" &&
                    item.beneficiary
            )
            .map(item => item.beneficiary);

    const beneficiaries =
        beneficiaryIds.length
            ? await Beneficiary.find({
                _id: {
                    $in: beneficiaryIds
                },
                organization:
                    organizationId
            })
                .select(LOCATION_FIELDS.join(" "))
                .lean()
            : [];

    const beneficiaryLocations =
        new Map(
            beneficiaries.map(
                beneficiary => [
                    String(beneficiary._id),
                    pickLocation(beneficiary)
                ]
            )
        );

    const activityRun =
        activityRunId
            ? await ActivityRun.findById(
                activityRunId
            )
                .select("region regionCode zone zoneCode woreda woredaCode location")
                .lean()
            : null;

    const runLocation =
        activityRun
            ? {
                ...pickLocation(activityRun),
                site:
                    activityRun.location || null
            }
            : null;

    const resolveLocation = (item) => {

        if (
            item.participantType === "Beneficiary"
        ) {

            const beneficiaryLocation =
                beneficiaryLocations.get(
                    String(item.beneficiary)
                );

            if (beneficiaryLocation) {
                return {
                    ...beneficiaryLocation,
                    site:
                        runLocation?.site || null
                };
            }

        }

        if (hasLocation(item.location)) {
            return item.location;
        }

        return hasLocation(runLocation)
            ? runLocation
            : null;

    };


    return resolveLocation;

};


// ==========================================
// SAVE ATTENDANCE RECORDS
// ==========================================

// The sheet is saved whole (people removed from it are
// removed), in one transaction: a failed save leaves the
// sheet as it was. With "version" (the sheet's
// recordsVersion when it was opened), a save over a sheet
// someone else saved in the meantime is refused instead of
// silently replacing their work. mode "add" keeps the people
// already on the sheet and adds the new ones.
const participantKey = (record) =>
    record.beneficiary ? `b:${record.beneficiary}`
        : record.staff ? `s:${record.staff}`
            : `x:${record.participantType}:${String(record.externalParticipant?.name || "").trim().toLowerCase()}:${String(record.externalParticipant?.organizationName || "").trim().toLowerCase()}`;

const saveAttendanceRecords = async (
    attendanceId,
    records,
    organizationId,
    userId,
    { version = null, mode = "replace" } = {}
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

    const currentVersion =
        Number(attendance.recordsVersion || 0);

    if (
        version !== null &&
        version !== undefined &&
        Number(version) !== currentVersion
    ) {
        throw new ApiError(
            "Someone else saved this attendance sheet after you opened it. Reload the sheet to see their changes, then make yours again.",
            409
        );
    }

    // ==========================================
    // Location snapshot
    // ==========================================

    const resolveLocation =
        await createAttendanceLocationResolver({
            organizationId,
            activityRunId:
                attendance.activityRun,
            participants:
                records
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
                        resolveLocation(item),

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
    // Save (one transaction)
    // ==========================================
    return runInTransaction(async (session) => {

        // the sheet must still be the version this save started from
        const claimed =
            await Attendance.updateOne(
                { _id: attendance._id, recordsVersion: currentVersion === 0 ? { $in: [null, 0] } : currentVersion },
                { $inc: { recordsVersion: 1 } },
                { session }
            );

        if (!claimed.matchedCount) {
            throw new ApiError(
                "Someone else saved this attendance sheet at the same moment. Reload the sheet and save again.",
                409
            );
        }

        let toInsert = preparedRecords;

        if (mode === "add") {
            const existing =
                await AttendanceRecord.find({ attendance: attendanceId, organization: organizationId })
                    .select("participantType beneficiary staff externalParticipant")
                    .session(session)
                    .lean();
            const onSheet = new Set(existing.map(participantKey));
            toInsert = preparedRecords.filter(record => !onSheet.has(participantKey(record)));
        }
        else {
            await AttendanceRecord.deleteMany(
                { attendance: attendanceId, organization: organizationId },
                { session }
            );
        }

        const saved =
            toInsert.length
                ? await AttendanceRecord.insertMany(toInsert, { session })
                : [];

        return { records: saved, version: currentVersion + 1 };

    });

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

            returnDocument: "after",

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

            returnDocument: "after"

        }

    );

};


module.exports = {

    createAttendanceLocationResolver,

    createAttendance,

    getAttendances,

    getAttendanceById,

    saveAttendanceRecords,

    getAttendanceRecords,

    updateAttendance,

    deleteAttendance

};
