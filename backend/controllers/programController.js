const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const {
    logActivity
} = require("../utils/auditLogger");


const {

    createProgram,

    getPrograms,

    getProgramById,

    updateProgram,

    deleteProgram,

    getProgramsLookup

} = require("../services/programservice");


const subscriptionService =
    require("../services/subscriptionService");


const Program =
    require("../models/program");



// ==========================================
// CREATE PROGRAM
// ==========================================

const createProgramController = async (

    req,

    res

) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==========================================
        // CHECK SUBSCRIPTION LIMIT
        // ==========================================

        await subscriptionService.checkResourceLimit(

            organizationId,

            "programs"

        );


        // ==========================================
        // CREATE PROGRAM
        // ==========================================

        const program =
            await createProgram(

                req.body,

                organizationId,

                req.user.userId

            );


        // ==========================================
        // AUDIT LOG
        // ==========================================

        await logActivity({

            req,

            action:
                "CREATE",

            module:
                "Program",

            entityType:
                "Program",

            entityId:
                program._id,

            description:
                `Program "${program.programName}" created`

        });


        // ==========================================
        // RESPONSE
        // ==========================================

        res.status(201).json({

            success: true,

            message:
                "Program created successfully",

            data:
                program

        });

    }

    catch (error) {

        console.error(

            "CREATE PROGRAM ERROR:",

            error

        );


        const statusCode =
            error.statusCode || 400;


        res.status(statusCode).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// GET ALL PROGRAMS
// ==========================================

const getProgramsController = async (

    req,

    res

) => {

    try {

        const programs =
            await getPrograms(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            message:
                "Programs fetched successfully",

            data:
                programs.data,

            pagination:
                programs.pagination

        });

    }

    catch (error) {

        console.error(

            "GET PROGRAMS ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// GET PROGRAM BY ID
// ==========================================

const getProgramByIdController = async (

    req,

    res

) => {

    try {

        const program =
            await getProgramById(

                req.params.id,

                req.user.organizationId

            );


        if (!program) {

            return res.status(404).json({

                success: false,

                message:
                    "Program not found"

            });

        }


        res.json({

            success: true,

            data:
                program

        });

    }

    catch (error) {

        console.error(

            "GET PROGRAM ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// UPDATE PROGRAM
// ==========================================

const updateProgramController = async (

    req,

    res

) => {

    try {

        const updated =
            await updateProgram(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        await logActivity({

            req,

            action:
                "UPDATE",

            module:
                "Program",

            entityType:
                "Program",

            entityId:
                updated._id,

            description:
                `Program "${updated.programName}" updated`

        });


        res.json({

            success: true,

            message:
                "Program updated successfully",

            data:
                updated

        });

    }

    catch (error) {

        console.error(

            "UPDATE PROGRAM ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// DELETE PROGRAM
// ==========================================

const deleteProgramController = async (

    req,

    res

) => {

    try {

        const program =
            await Program.findOne({

                _id:
                    req.params.id,

                organization:
                    req.user.organizationId,

                isDeleted:
                    false

            });


        if (!program) {

            return res.status(404).json({

                success: false,

                message:
                    "Program not found"

            });

        }


        await deleteProgram(

            req.params.id,

            req.user.organizationId,

            req.user.userId

        );


        await logActivity({

            req,

            action:
                "DELETE",

            module:
                "Program",

            entityType:
                "Program",

            entityId:
                program._id,

            description:
                `Program "${program.programName}" deleted`,

            severity:
                "warning"

        });


        res.json({

            success: true,

            message:
                "Program deleted successfully"

        });

    }

    catch (error) {

        console.error(

            "DELETE PROGRAM ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// PROGRAM LOOKUP
// ==========================================

const getProgramsLookupController = async (

    req,

    res

) => {

    try {

        const programs =
            await getProgramsLookup(

                req.user.organizationId

            );


        res.json({

            success: true,

            data:
                programs

        });

    }

    catch (error) {

        console.error(

            "PROGRAM LOOKUP ERROR:",

            error

        );


        res.status(getErrorStatus(error)).json({

            success: false,

            message:
                getErrorMessage(error)

        });

    }

};



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createProgramController,

    getProgramsController,

    getProgramByIdController,

    updateProgramController,

    deleteProgramController,

    getProgramsLookupController

};