const mongoose = require("mongoose");

const {
    ROLES,
    USER_STATUS
} = require("../config/constants");


const userSchema = new mongoose.Schema(

{

    /*
        Super Admin:
        organization = null

        NGO Users:
        organization = NGO id
    */

    organization: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Organization",

        required: function(){

            return this.role !== ROLES.SUPER_ADMIN;

        }

    },


    name: {

        type:String,

        required:true,

        trim:true

    },


    email: {

        type:String,

        required:true,

        unique:true,

        lowercase:true,

        trim:true

    },


    password: {

        type:String,

        required:true,

        minlength:6

    },


    role: {

        type:String,

        enum:Object.values(ROLES),

        default:ROLES.VIEWER

    },


    status: {

        type:String,

        enum:Object.values(USER_STATUS),

        default:USER_STATUS.ACTIVE

    },


    lastLogin: {

        type:Date,

        default:null

    }


},

{

    timestamps:true

}

);


module.exports = mongoose.model(
    "User",
    userSchema
);