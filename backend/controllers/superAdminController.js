const bcrypt = require("bcrypt");
const User = require("../models/user");

const { USER_STATUS } = require("../config/constants"); 


const createOrganizationAdmin = async (req,res)=>{

    try{

        const {
            organizationId,
            name,
            email,
            password
        } = req.body;


        if(!organizationId){

            return res.status(400).json({

                success:false,
                message:"Organization ID required"

            });

        }


        const existing = await User.findOne({

            email

        });


        if(existing){

            return res.status(400).json({

                success:false,
                message:"Email already exists"

            });

        }


        const hashedPassword =
            await bcrypt.hash(
                password,
                10
            );


        const user = await User.create({

    organization:
        organizationId,

    name,

    email,

    password:
        hashedPassword,

    role:
        "organization_admin",

    status:
        USER_STATUS.ACTIVE

});
    

        res.status(201).json({

            success:true,

            message:
            "Organization admin created successfully",

            data:{
                id:user._id,
                name:user.name,
                email:user.email,
                role:user.role
            }

        });


    }
    catch(error){

        res.status(500).json({

            success:false,
            message:error.message

        });

    }

};


module.exports={
    createOrganizationAdmin
};