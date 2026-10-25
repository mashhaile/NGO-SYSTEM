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

    // A role the organization made (models/Role.js): its
    // permissions replace those of the built-in role, which
    // is kept as Viewer underneath
    customRole: {
        type:mongoose.Schema.Types.ObjectId,
        ref:"Role",
        default:null
    },


    status: {

        type:String,

        enum:Object.values(USER_STATUS),

        default:USER_STATUS.ACTIVE

    },


    lastLogin: {

        type:Date,

        default:null

    },


    // ==========================================
    // PASSWORD SECURITY
    // ==========================================

    // Failed logins in a row; reset on success.

    failedLoginAttempts: {

        type:Number,

        default:0

    },

    // While in the future, login is refused.

    lockUntil: {

        type:Date,

        default:null

    },

    // Set by an admin reset: the user must choose a new
    // password before using the system.

    mustChangePassword: {

        type:Boolean,

        default:false

    },

    // Tokens issued before this are no longer accepted
    // (logs out other sessions after a change / reset).

    passwordChangedAt: {

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