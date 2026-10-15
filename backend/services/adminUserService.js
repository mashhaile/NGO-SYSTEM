const bcrypt =
require("bcrypt");


const User =
require("../models/user");


const Organization =
require("../models/organization");


const {
    ROLES,
    USER_STATUS
} =
require("../config/constants");




// ==========================================
// Create User By Super Admin
// ==========================================

const createUser = async (
    data
) => {


    const {

        name,

        email,

        password,

        role,

        organizationId

    } = data;




    if(
        role !== ROLES.SUPER_ADMIN
        &&
        !organizationId
    ){

        throw new Error(
            "Organization information missing"
        );

    }




    if(organizationId){


        const organization =
            await Organization.findOne({

                _id:organizationId,

                isDeleted:false

            });



        if(!organization){

            throw new Error(
                "Organization not found"
            );

        }


    }




    const existing =
        await User.findOne({

            email

        });



    if(existing){

        throw new Error(
            "Email already exists"
        );

    }




    const hashedPassword =
        await bcrypt.hash(

            password,

            10

        );





    const user =
        await User.create({

            organization:
                organizationId || null,

            name,

            email,

            password:
                hashedPassword,

            role,

            status:
                USER_STATUS.ACTIVE

        });




    return {

        id:user._id,

        name:user.name,

        email:user.email,

        role:user.role,

        organization:user.organization,

        status:user.status

    };


};





// ==========================================
// Get All Users
// ==========================================

const getUsers = async () => {


    const users =
        await User.find({

            isDeleted:false

        })

        .select("-password")

        .populate(

            "organization",

            "name organizationCode"

        );



    return users;


};





// ==========================================
// Get User Details
// ==========================================

const getUserById = async (
    id
)=>{


    const user =
        await User.findOne({

            _id:id,

            isDeleted:false

        })

        .select("-password")

        .populate(

            "organization",

            "name organizationCode"

        );



    return user;

};





module.exports = {

    createUser,

    getUsers,

    getUserById

};