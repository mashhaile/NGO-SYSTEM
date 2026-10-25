const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const attendanceService = require("../services/attendanceService");




// ==========================================
// CREATE ATTENDANCE SESSION
// ==========================================

const createAttendance = async (req,res)=>{

    try{


        const attendance =
        await attendanceService.createAttendance(

            req.body,

            req.user.organizationId,

            req.user.userId

        );


        res.status(201).json({

            success:true,

            data:attendance

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
// GET ALL ATTENDANCE
// ==========================================

const getAttendances = async(req,res)=>{


    try{


        const result =
        await attendanceService.getAttendances(

            req.user.organizationId,

            req.query

        );


        res.json({

            success:true,

            ...result

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
// GET SINGLE ATTENDANCE
// ==========================================

const getAttendanceById = async(req,res)=>{


    try{


        const attendance =
        await attendanceService.getAttendanceById(

            req.params.id,

            req.user.organizationId

        );



        if(!attendance){


            return res.status(404).json({

                success:false,

                message:"Attendance not found"

            });


        }




        res.json({

            success:true,

            data:attendance

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
// SAVE ATTENDANCE RECORDS
// ==========================================

const saveAttendanceRecords = async(req,res)=>{


    try{


        const {
            records,
            version,
            mode
        } = req.body;



        if(!Array.isArray(records)){


            return res.status(400).json({

                success:false,

                message:
                "Attendance records must be an array"

            });


        }





        const saved =
        await attendanceService.saveAttendanceRecords(
            req.params.id,
            records,
            req.user.organizationId,
            req.user.userId,
            {
                version: version ?? null,
                mode: mode === "add" ? "add" : "replace"
            }
        );
        res.status(200).json({
            success:true,
            data:saved.records,
            // the sheet's new version (for the next save)
            version:saved.version
        });



    }
    catch(error){


        console.error(

            "SAVE ATTENDANCE RECORD ERROR:",

            error

        );



        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


};









// ==========================================
// GET ATTENDANCE RECORDS
// ==========================================

const getAttendanceRecords = async(req,res)=>{


    try{


        const records =

        await attendanceService.getAttendanceRecords(

            req.params.id,

            req.user.organizationId

        );



        res.json({

            success:true,

            data:records

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
// UPDATE ATTENDANCE SESSION
// ==========================================

const updateAttendance = async(req,res)=>{


    try{


        const attendance =

        await attendanceService.updateAttendance(

            req.params.id,

            req.body,

            req.user.organizationId,

            req.user.userId

        );



        res.json({

            success:true,

            data:attendance

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
// DELETE ATTENDANCE SESSION
// ==========================================

const deleteAttendance = async(req,res)=>{


    try{


        await attendanceService.deleteAttendance(

            req.params.id,

            req.user.organizationId,

            req.user.userId

        );



        res.json({

            success:true,

            message:
            "Attendance deleted successfully"

        });



    }
    catch(error){


        res.status(getErrorStatus(error)).json({

            success:false,

            message:getErrorMessage(error)

        });


    }


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