const Donation =
    require("../models/donation");

const Donor =
    require("../models/Donor");

const Program =
    require("../models/Program");

const Project =
    require("../models/Project");

const Activity =
    require("../models/Activity");

const ActivityRun =
    require("../models/ActivityRun");


// ==========================================
// GENERATE DONATION CODE
// ==========================================

const generateDonationCode = async (
    organizationId
) => {

    let number =
        await Donation.countDocuments({
            organization: organizationId
        }) + 1;


    while (true) {

        const code =
            `DON-${String(number).padStart(4, "0")}`;


        const exists =
            await Donation.exists({

                organization:
                    organizationId,

                donationCode:
                    code

            });


        if (!exists) {

            return code;

        }


        number++;

    }

};

// ==========================================
// VALIDATE REFERENCES
// ==========================================

const validateReferences = async (
    data,
    organizationId
) => {

    // ==========================================
    // DONOR
    // ==========================================

    if (!data.donor) {

        throw new Error(
            "Donor is required."
        );

    }


    const donor =
        await Donor.findOne({

            _id:
                data.donor,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donor) {

        throw new Error(
            "Donor not found."
        );

    }


    // ==========================================
    // PROGRAM
    // ==========================================

    let program = null;


    if (data.program) {

        program =
            await Program.findOne({

                _id:
                    data.program,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!program) {

            throw new Error(
                "Program not found."
            );

        }

    }


    // ==========================================
    // PROJECT
    // ==========================================

    let project = null;


    if (data.project) {

        project =
            await Project.findOne({

                _id:
                    data.project,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!project) {

            throw new Error(
                "Project not found."
            );

        }


        // ======================================
        // PROJECT → PROGRAM
        // ======================================

        if (program) {

            const projectProgramId =
                normalizeId(
                    project.program
                );


            if (
                projectProgramId !==
                program._id.toString()
            ) {

                throw new Error(
                    "Selected project does not belong to the selected program."
                );

            }

        }

    }


    // ==========================================
    // ACTIVITY
    // ==========================================

    let activity = null;


    if (data.activity) {

        // --------------------------------------
        // If a project is selected, find the
        // activity directly under that project.
        // --------------------------------------

        const activityFilter = {

            _id:
                data.activity,

            organization:
                organizationId,

            isDeleted:
                false

        };


        if (project) {

            activityFilter.project =
                project._id;

        }


        activity =
            await Activity.findOne(
                activityFilter
            );


        if (!activity) {

            if (project) {

                throw new Error(
                    "Selected activity does not belong to the selected project."
                );

            }

            throw new Error(
                "Activity not found."
            );

        }

    }


    // ==========================================
    // ACTIVITY RUN
    // ==========================================

    let activityRun = null;


    if (data.activityRun) {

        // --------------------------------------
        // If an activity is selected, find the
        // run directly under that activity.
        // --------------------------------------

        const activityRunFilter = {

            _id:
                data.activityRun,

            organization:
                organizationId,

            isDeleted:
                false

        };


        if (activity) {

            activityRunFilter.activity =
                activity._id;

        }


        activityRun =
            await ActivityRun.findOne(
                activityRunFilter
            );


        if (!activityRun) {

            if (activity) {

                throw new Error(
                    "Selected activity run does not belong to the selected activity."
                );

            }

            throw new Error(
                "Activity run not found."
            );

        }

    }

};


// ==========================================
// NORMALIZE RELATIONSHIP ID
// ==========================================

const normalizeId = (
    value
) => {

    if (!value) {
        return null;
    }


    if (
        typeof value === "object" &&
        value._id
    ) {

        return value._id.toString();

    }


    return value.toString();

};



// ==========================================
// POPULATE DONATION
// ==========================================

const populateDonation = (query) => {

    return query

        .populate(
            "donor",
            "name donorType email phone"
        )

        .populate(
            "program",
            "name programCode"
        )

        .populate(
            "project",
            "name projectCode"
        )

        .populate(
            "activity",
            "name activityCode"
        )

        .populate(
            "activityRun",
            "runCode name"
        );

};


// ==========================================
// CREATE DONATION
// ==========================================

const createDonation = async (
    data,
    organizationId,
    userId
) => {

    await validateReferences(
        data,
        organizationId
    );


    const donationCode =
        await generateDonationCode(
            organizationId
        );


    const donation =
        await Donation.create({

            ...data,

            organization:
                organizationId,

            donationCode,

            createdBy:
                userId

        });


    return populateDonation(
        Donation.findById(
            donation._id
        )
    );

};


// ==========================================
// GET ALL DONATIONS
// ==========================================

const getDonations = async (
    organizationId,
    query = {}
) => {

    const filter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    if (query.donor) {

        filter.donor =
            query.donor;

    }


    if (query.program) {

        filter.program =
            query.program;

    }


    if (query.project) {

        filter.project =
            query.project;

    }


    if (query.activity) {

        filter.activity =
            query.activity;

    }


    if (query.activityRun) {

        filter.activityRun =
            query.activityRun;

    }


    if (query.status) {

        filter.status =
            query.status;

    }


    return populateDonation(

        Donation.find(filter)

            .sort({

                donationDate:
                    -1

            })

    );

};


// ==========================================
// GET SINGLE DONATION
// ==========================================

const getDonationById = async (
    id,
    organizationId
) => {

    return populateDonation(

        Donation.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        })

    );

};


// ==========================================
// UPDATE DONATION
// ==========================================

const updateDonation = async (
    id,
    data,
    organizationId,
    userId
) => {

    const donation =
        await Donation.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donation) {

        throw new Error(
            "Donation not found."
        );

    }


    // ==========================================
    // BUILD REFERENCE VALIDATION DATA
    // ==========================================

    const references = {

        donor:
            data.donor ??
            donation.donor,

        program:
            data.program ??
            donation.program,

        project:
            data.project ??
            donation.project,

        activity:
            data.activity ??
            donation.activity,

        activityRun:
            data.activityRun ??
            donation.activityRun

    };


    await validateReferences(
        references,
        organizationId
    );


    // ==========================================
    // ALLOWED UPDATE FIELDS
    // ==========================================

    const allowedFields = [

        "donor",

        "program",

        "project",

        "activity",

        "activityRun",

        "title",

        "amount",

        "currency",

        "donationDate",

        "financialYear",

        "fundingSource",

        "fundingRestriction",

        "donationType",

        "status",

        "receiptNumber",

        "referenceNumber",

        "description"

    ];


    allowedFields.forEach(
        field => {

            if (
                data[field] !==
                undefined
            ) {

                donation[field] =
                    data[field];

            }

        }
    );


    donation.updatedBy =
        userId;


    await donation.save();


    return populateDonation(

        Donation.findById(
            donation._id
        )

    );

};


// ==========================================
// DELETE DONATION
// ==========================================

const deleteDonation = async (
    id,
    organizationId,
    userId
) => {

    const donation =
        await Donation.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donation) {

        throw new Error(
            "Donation not found."
        );

    }


    donation.isDeleted =
        true;


    donation.deletedAt =
        new Date();


    donation.deletedBy =
        userId;


    await donation.save();


    return donation;

};


// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createDonation,

    getDonations,

    getDonationById,

    updateDonation,

    deleteDonation

};