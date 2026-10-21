const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const {
    logActivity
} = require("../utils/auditLogger");


const {

    createEnrollment,

    getEnrollments,

    getEnrollmentById,

    updateEnrollment,

    deleteEnrollment

} = require("../services/enrollmentService");


const Enrollment =
require("../models/enrollment");





// ==========================================
// CREATE ENROLLMENT
// ==========================================

const createEnrollmentController = async (

    req,

    res

)=>{


    try{


        const enrollment =

        await createEnrollment(

            req.body,

            req.user.organizationId,

            req.user.userId

        );



        await logActivity({

            req,

            action:"CREATE",

            module:"Enrollment",

            entityType:"Enrollment",

            entityId:enrollment._id,

            description:
            "New beneficiary enrollment created"

        });



        res.status(201).json({

            success:true,

            message:
            "Enrollment created successfully",

            data:enrollment

        });


    }

    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};





// ==========================================
// GET ALL ENROLLMENTS
// ==========================================

const getEnrollmentsController = async (

    req,

    res

)=>{


    try{


        const enrollments =

        await getEnrollments(

            req.user.organizationId,

            req.query

        );



        res.json({

            success:true,

            message:
            "Enrollments fetched successfully",

            data:enrollments.data,

            pagination:
            enrollments.pagination

        });



    }

    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};





// ==========================================
// GET BY ID
// ==========================================

const getEnrollmentByIdController = async (

    req,

    res

)=>{


    try{


        const enrollment =

        await getEnrollmentById(

            req.params.id,

            req.user.organizationId

        );



        res.json({

            success:true,

            data:enrollment

        });



    }

    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};





// ==========================================
// UPDATE ENROLLMENT
// ==========================================

const updateEnrollmentController = async (

    req,

    res

)=>{


    try{


        const updated =

        await updateEnrollment(

            req.params.id,

            req.body,

            req.user.organizationId,

            req.user.userId

        );



        await logActivity({

            req,

            action:"UPDATE",

            module:"Enrollment",

            entityType:"Enrollment",

            entityId:updated._id,

            description:
            "Enrollment updated"

        });



        res.json({

            success:true,

            message:
            "Enrollment updated successfully",

            data:updated

        });



    }

    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};





// ==========================================
// DELETE ENROLLMENT
// ==========================================

const deleteEnrollmentController = async (

    req,

    res

)=>{


    try{


        const enrollment =

        await Enrollment.findOne({

            _id:req.params.id,

            organization:
            req.user.organizationId,

            isDeleted:false

        });



        if(!enrollment){


            return res.status(404).json({

                success:false,

                message:
                "Enrollment not found"

            });


        }



        await deleteEnrollment(

            req.params.id,

            req.user.organizationId,

            req.user.userId

        );



        await logActivity({

            req,

            action:"DELETE",

            module:"Enrollment",

            entityType:"Enrollment",

            entityId:enrollment._id,

            description:
            "Enrollment deleted",

            severity:"warning"

        });



        res.json({

            success:true,

            message:
            "Enrollment deleted successfully"

        });



    }

    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};





module.exports={


    createEnrollmentController,

    getEnrollmentsController,

    getEnrollmentByIdController,

    updateEnrollmentController,

    deleteEnrollmentController


};