const mongoose = require("mongoose");

const attendanceRecordSchema = new mongoose.Schema(
    {
        // =====================================
        // Tenant
        // =====================================

        organization: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Organization",
            required: true,
            index: true
        },

        // =====================================
        // Attendance Session
        // =====================================

        attendance: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Attendance",
            required: true,
            index: true
        },

        // =====================================
        // Activity Hierarchy
        // =====================================

        activityRun: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "ActivityRun",
            required: true,
            index: true
        },

        project: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Project",
            required: true,
            index: true
        },

        program: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Program",
            required: true,
            index: true
        },

        // =====================================
        // Participant Type
        // =====================================

        participantType: {
            type: String,
            enum: [
                "Beneficiary",
                "Staff",
                "Board",
                "Partner",
                "Government",
                "Community",
                "Other"
            ],
            required: true,
            index: true
        },

        // =====================================
        // Demographic Snapshot
        // =====================================

        gender: {
            type: String,
            enum: [
                "Male",
                "Female",
                "Other",
                "Prefer not to say"
            ],
            default: null,
            index: true
        },

        ageGroup: {
            type: String,
            enum: [
                "Child",
                "Youth",
                "Adult",
                "Elderly",
                "Unknown"
            ],
            default: null
        },

        disabilityStatus: {
            type: Boolean,
            default: false
        },

        // =====================================
        // Location Snapshot
        // =====================================

        location: {
            region: {
                type: String,
                trim: true,
                default: null
            },

            // Official P-codes (AdminArea)

            regionCode: {
                type: String,
                trim: true,
                default: null
            },

            zoneCode: {
                type: String,
                trim: true,
                default: null
            },

            woredaCode: {
                type: String,
                trim: true,
                default: null
            },

            zone: {
                type: String,
                trim: true,
                default: null
            },

            woreda: {
                type: String,
                trim: true,
                default: null
            },

            kebele: {
                type: String,
                trim: true,
                default: null
            },

            village: {
                type: String,
                trim: true,
                default: null
            },

            site: {
                type: String,
                trim: true,
                default: null
            },

            latitude: {
                type: Number,
                default: null
            },

            longitude: {
                type: Number,
                default: null
            }
        },

        // =====================================
        // Internal Participants
        // =====================================

        beneficiary: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Beneficiary",
            default: null,
            index: true
        },

        staff: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
            index: true
        },

        // =====================================
        // External Participants
        // =====================================

        externalParticipant: {
            name: {
                type: String,
                trim: true,
                default: null
            },

            gender: {
                type: String,
                enum: [
                    "Male",
                    "Female",
                    "Other",
                    "Prefer not to say"
                ],
                default: null
            },

            organizationName: {
                type: String,
                trim: true,
                default: null
            },

            position: {
                type: String,
                trim: true,
                default: null
            },

            phone: {
                type: String,
                trim: true,
                default: null
            },

            email: {
                type: String,
                trim: true,
                lowercase: true,
                default: null
            }
        },

        // =====================================
        // Attendance Status
        // =====================================

        status: {
            type: String,
            enum: [
                "Present",
                "Absent",
                "Late",
                "Excused"
            ],
            default: "Present",
            index: true
        },

        checkInTime: {
            type: Date,
            default: null
        },

        checkOutTime: {
            type: Date,
            default: null
        },

        notes: {
            type: String,
            default: null
        },

        // =====================================
        // Audit
        // =====================================

        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        updatedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        },

        // =====================================
        // Soft Delete
        // =====================================

        isDeleted: {
            type: Boolean,
            default: false,
            index: true
        },

        deletedAt: {
            type: Date,
            default: null
        },

        deletedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null
        }
    },
    {
        timestamps: true
    }
);

// =====================================
// Duplicate Prevention
// =====================================

// Beneficiary

attendanceRecordSchema.index(
    {
        attendance: 1,
        beneficiary: 1
    },
    {
        unique: true,
        partialFilterExpression: {
            participantType: "Beneficiary",
            beneficiary: {
                $type: "objectId"
            }
        }
    }
);

// Staff

attendanceRecordSchema.index(
    {
        attendance: 1,
        staff: 1
    },
    {
        unique: true,
        partialFilterExpression: {
            participantType: "Staff",
            staff: {
                $type: "objectId"
            }
        }
    }
);

// =====================================
// Reporting Indexes
// =====================================

attendanceRecordSchema.index({
    organization: 1,
    attendance: 1
});

attendanceRecordSchema.index({
    organization: 1,
    activityRun: 1
});

attendanceRecordSchema.index({
    organization: 1,
    project: 1
});

attendanceRecordSchema.index({
    organization: 1,
    program: 1
});

attendanceRecordSchema.index({
    organization: 1,
    participantType: 1
});

attendanceRecordSchema.index({
    organization: 1,
    gender: 1
});

attendanceRecordSchema.index({
    organization: 1,
    ageGroup: 1
});

attendanceRecordSchema.index({
    organization: 1,
    status: 1
});

attendanceRecordSchema.index({
    organization: 1,
    "location.region": 1
});

attendanceRecordSchema.index({
    organization: 1,
    "location.regionCode": 1
});

attendanceRecordSchema.index({
    organization: 1,
    "location.woreda": 1
});

attendanceRecordSchema.index({
    organization: 1,
    "location.site": 1
});

// dates that must make sense (see plugins/dateRules)
attendanceRecordSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This attendance",
        rules: [
            {
                fields: ["checkInTime", "checkOutTime"],
                check: (v) =>
                    v.checkInTime && v.checkOutTime && new Date(v.checkOutTime) < new Date(v.checkInTime)
                        ? "The check-out time is before the check-in time."
                        : null
            }
        ]
    }
);


module.exports = mongoose.model(
    "AttendanceRecord",
    attendanceRecordSchema
);
