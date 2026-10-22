const {
    getPagination
} = require("../utils/pagination");

const {
    buildSearch
} = require("../utils/searchBuilder");

const Program = require("../models/program");

const {
    getBudgetFigures
} = require("./budgetFigures");


// ==========================================
// GENERATE PROGRAM CODE
// ==========================================

const generateProgramCode = async (organizationId) => {

    const lastProgram = await Program.findOne({
        organization: organizationId,
        programCode: {
            $regex: /^PRG-\d+$/
        }
    })
        .sort({
            createdAt: -1
        })
        .select("programCode")
        .lean();


    let nextNumber = 1;


    if (
        lastProgram &&
        lastProgram.programCode
    ) {

        const lastNumber = parseInt(
            lastProgram.programCode.replace(
                "PRG-",
                ""
            ),
            10
        );


        if (!Number.isNaN(lastNumber)) {

            nextNumber =
                lastNumber + 1;

        }

    }


    return (
        "PRG-" +
        String(nextNumber).padStart(
            6,
            "0"
        )
    );

};


// ==========================================
// CREATE PROGRAM
// ==========================================

const createProgram = async (
    data,
    organizationId,
    userId
) => {

    if (!organizationId) {
        throw new Error(
            "Organization ID is required"
        );
    }


    if (!data.name || !data.name.trim()) {
        throw new Error(
            "Program name is required"
        );
    }


    if (!data.startDate) {
        throw new Error(
            "Start date is required"
        );
    }


    // --------------------------------------
    // Generate program code
    // --------------------------------------

    const programCode =
        await generateProgramCode(
            organizationId
        );


    // --------------------------------------
    // Prepare clean payload
    // --------------------------------------

    const programData = {

        organization:
            organizationId,

        programCode,

        name:
            data.name.trim(),

        description:
            data.description?.trim() || null,

        category:
            data.category?.trim() || null,

        targetBeneficiaries:
            Number(
                data.targetBeneficiaries || 0
            ),

        startDate:
            data.startDate,

        // IMPORTANT:
        // Empty string must become null

        endDate:
            data.endDate
                ? data.endDate
                : null,

        status:
            data.status || "Planned",

        createdBy:
            userId

    };


    // --------------------------------------
    // Create
    // --------------------------------------

    try {

        const program =
            await Program.create(
                programData
            );


        return program;

    }
    catch (error) {

        console.error(
            "CREATE PROGRAM SERVICE ERROR:",
            error
        );


        // Return useful validation message

        if (
            error.name ===
            "ValidationError"
        ) {

            const messages =
                Object.values(
                    error.errors
                ).map(
                    item =>
                        item.message
                );


            throw new Error(
                messages.join(", ")
            );

        }


        // Duplicate program code

        if (
            error.code === 11000
        ) {

            throw new Error(
                "Program code already exists. Please try again."
            );

        }


        throw error;

    }

};


// ==========================================
// GET ALL PROGRAMS
// ==========================================

const getPrograms = async (
    organizationId,
    query = {}
) => {

    const {
        search,
        status
    } = query;


    const {
        page,
        limit,
        skip
    } = getPagination(query);


    const filter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    Object.assign(
        filter,
        buildSearch(
            search,
            [
                "name",
                "programCode",
                "description"
            ]
        )
    );


    if (status) {

        filter.status =
            status;

    }


    const [
        programs,
        total
    ] = await Promise.all([

        Program.find(filter)

            .select(
                [
                    "programCode",
                    "name",
                    "category",
                    "description",
                    "status",
                    "startDate",
                    "endDate",
                    "targetBeneficiaries"
                ]
            )

            .sort({
                createdAt: -1
            })

            .skip(skip)

            .limit(limit)

            .lean(),


        Program.countDocuments(
            filter
        )

    ]);


    // Budget from the Budgets module
    const figures =
        await getBudgetFigures(
            organizationId,
            { programIds: programs.map(program => program._id) }
        );

    return {

        data:
            programs.map(program => ({
                ...program,
                budget: figures.programs[String(program._id)] || null
            })),

        pagination: {

            total,

            page,

            limit,

            totalPages:
                Math.ceil(
                    total / limit
                )

        }

    };

};


// ==========================================
// GET PROGRAM BY ID
// ==========================================

const getProgramById = async (
    id,
    organizationId
) => {

    const program =
        await Program.findOne({

            _id: id,

            organization:
                organizationId,

            isDeleted:
                false

        })
            .lean();


    if (!program) {

        throw new Error(
            "Program not found"
        );

    }


    // Budget from the Budgets module (old typed value ignored)
    const figures =
        await getBudgetFigures(
            organizationId,
            { programIds: [program._id] }
        );

    return {
        ...program,
        budget: figures.programs[String(program._id)] || null
    };

};


// ==========================================
// UPDATE PROGRAM
// ==========================================

const updateProgram = async (
    id,
    data,
    organizationId,
    userId
) => {

    const program =
        await Program.findOne({

            _id: id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!program) {

        throw new Error(
            "Program not found"
        );

    }


    // Never allow these to be changed
    delete data.organization;
    delete data.programCode;

    // Budgets are set in the Budgets module only
    delete data.budget;


    // Empty endDate => null

    if (
        data.endDate === ""
    ) {

        data.endDate = null;

    }


    // Convert numeric fields

    if (
        data.targetBeneficiaries !==
        undefined
    ) {

        data.targetBeneficiaries =
            Number(
                data.targetBeneficiaries || 0
            );

    }


    Object.assign(
        program,
        data
    );


    program.updatedBy =
        userId;


    try {

        await program.save();

        return program;

    }
    catch (error) {

        console.error(
            "UPDATE PROGRAM ERROR:",
            error
        );


        if (
            error.name ===
            "ValidationError"
        ) {

            const messages =
                Object.values(
                    error.errors
                ).map(
                    item =>
                        item.message
                );


            throw new Error(
                messages.join(", ")
            );

        }


        throw error;

    }

};


// ==========================================
// DELETE PROGRAM
// ==========================================

const deleteProgram = async (
    id,
    organizationId,
    userId
) => {

    const program =
        await Program.findOne({

            _id: id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!program) {

        throw new Error(
            "Program not found"
        );

    }


    program.isDeleted =
        true;

    program.deletedAt =
        new Date();

    program.deletedBy =
        userId;


    await program.save();


    return program;

};


// ==========================================
// PROGRAM LOOKUP
// ==========================================

const getProgramsLookup = async (
    organizationId
) => {

    const programs =
        await Program.find({

            organization:
                organizationId,

            isDeleted:
                false

        })
            .select(
                "_id programCode name"
            )
            .sort({
                createdAt: -1
            })
            .lean();


    return programs;

};


// ==========================================
// EXPORT
// ==========================================

module.exports = {

    createProgram,

    getPrograms,

    getProgramById,

    updateProgram,

    deleteProgram,

    getProgramsLookup

};