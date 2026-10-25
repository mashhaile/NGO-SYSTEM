const { WORK_STATUS_INPUT } = require("../constants/workStatus");
const Joi = require("joi");


// ======================================================
// CREATE ACTIVITY
// ======================================================

exports.createActivitySchema = Joi.object({

    project:
        Joi.string()
            .required(),

    name:
        Joi.string()
            .trim()
            .min(3)
            .required(),

    activityType:
        Joi.string()
            .valid(
                "Training",
                "Workshop",
                "Seminar",
                "Meeting",
                "Conference",
                "Awareness Campaign",
                "Field Visit",
                "Monitoring Visit",
                "Assessment",
                "Distribution",
                "Community Dialogue",
                "Other"
            )
            .default("Training"),

    participantSource:
        Joi.string()
            .valid(
                "Enrolled Beneficiaries",
                "Staff",
                "Board Members",
                "Volunteers",
                "Partners",
                "External Participants",
                "Mixed"
            )
            .default("Enrolled Beneficiaries"),

    targetGroups:
        Joi.array()
            .items(
                Joi.string().valid(
                    "Women",
                    "Men",
                    "Youth",
                    "Children",
                    "Persons with Disabilities",
                    "Farmers",
                    "Entrepreneurs",
                    "Students",
                    "Teachers",
                    "Health Workers",
                    "Community Leaders",
                    "Staff",
                    "Board Members",
                    "Partners",
                    "Government Officials",
                    "General Public"
                )
            )
            .default([]),

    description:
        Joi.string()
            .allow("")
            .allow(null),

    activityDate:
        Joi.date()
            .required(),

    region:
        Joi.string()
            .trim()
            .allow("", null),

    regionCode:
        Joi.string()
            .trim()
            .allow("", null),

    zone:
        Joi.string()
            .trim()
            .allow("", null),

    zoneCode:
        Joi.string()
            .trim()
            .allow("", null),

    woreda:
        Joi.string()
            .trim()
            .allow("", null),

    woredaCode:
        Joi.string()
            .trim()
            .allow("", null),

    location:
        Joi.string()
            .allow("")
            .allow(null),

    facilitator:
        Joi.string()
            .allow("")
            .allow(null),

    targetParticipants:
        Joi.number()
            .min(0)
            .default(0),

    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT)
            .default("Planned"),

    remarks:
        Joi.string()
            .allow("")
            .allow(null)

});


// ======================================================
// UPDATE ACTIVITY
// ======================================================

exports.updateActivitySchema = Joi.object({

    project:
        Joi.string(),

    name:
        Joi.string()
            .trim()
            .min(3),

    activityType:
        Joi.string()
            .valid(
                "Training",
                "Workshop",
                "Seminar",
                "Meeting",
                "Conference",
                "Awareness Campaign",
                "Field Visit",
                "Monitoring Visit",
                "Assessment",
                "Distribution",
                "Community Dialogue",
                "Other"
            ),

    participantSource:
        Joi.string()
            .valid(
                "Enrolled Beneficiaries",
                "Staff",
                "Board Members",
                "Volunteers",
                "Partners",
                "External Participants",
                "Mixed"
            ),

    targetGroups:
        Joi.array()
            .items(
                Joi.string().valid(
                    "Women",
                    "Men",
                    "Youth",
                    "Children",
                    "Persons with Disabilities",
                    "Farmers",
                    "Entrepreneurs",
                    "Students",
                    "Teachers",
                    "Health Workers",
                    "Community Leaders",
                    "Staff",
                    "Board Members",
                    "Partners",
                    "Government Officials",
                    "General Public"
                )
            ),

    description:
        Joi.string()
            .allow("")
            .allow(null),

    activityDate:
        Joi.date(),

    region:
        Joi.string()
            .trim()
            .allow("", null),

    regionCode:
        Joi.string()
            .trim()
            .allow("", null),

    zone:
        Joi.string()
            .trim()
            .allow("", null),

    zoneCode:
        Joi.string()
            .trim()
            .allow("", null),

    woreda:
        Joi.string()
            .trim()
            .allow("", null),

    woredaCode:
        Joi.string()
            .trim()
            .allow("", null),

    location:
        Joi.string()
            .allow("")
            .allow(null),

    facilitator:
        Joi.string()
            .allow("")
            .allow(null),

    targetParticipants:
        Joi.number()
            .min(0),

    status:
        Joi.string()
            .valid(...WORK_STATUS_INPUT),

    remarks:
        Joi.string()
            .allow("")
            .allow(null)

});