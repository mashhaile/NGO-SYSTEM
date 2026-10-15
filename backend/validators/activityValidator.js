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
            .valid(
                "Planned",
                "Ongoing",
                "Completed",
                "Cancelled"
            )
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
            .valid(
                "Planned",
                "Ongoing",
                "Completed",
                "Cancelled"
            ),

    remarks:
        Joi.string()
            .allow("")
            .allow(null)

});