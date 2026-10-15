const service =
require("../services/adminUserService");




// ==========================================
// Create User
// ==========================================

const createUser = async (

    req,

    res

) => {

    try {


        const data =
            await service.createUser(
                req.body
            );


        res.status(201).json({

            success:true,

            message:
            "User created successfully",

            data

        });


    }
    catch(error){

        res.status(500).json({

            success:false,

            message:error.message

        });

    }

};





// ==========================================
// Get Users
// ==========================================

const getUsers = async (

    req,

    res

) => {

    try {


        const data =
            await service.getUsers();



        res.json({

            success:true,

            data

        });


    }
    catch(error){


        res.status(500).json({

            success:false,

            message:error.message

        });


    }

};





// ==========================================
// Get User Details
// ==========================================

const getUserDetails = async (

    req,

    res

) => {

    try {


        const data =
            await service.getUserById(

                req.params.id

            );



        if(!data){

            return res.status(404).json({

                success:false,

                message:
                "User not found"

            });

        }



        res.json({

            success:true,

            data

        });


    }
    catch(error){

        res.status(500).json({

            success:false,

            message:error.message

        });

    }

};





module.exports = {


    createUser,

    getUsers,

    getUserDetails

};