const mongoose = require("mongoose");


const NotificationSchema =
new mongoose.Schema(

{

    // Organization scope

    organization: {

        type:
        mongoose.Schema.Types.ObjectId,

        ref:
        "Organization",

        required:true

    },


    // User specific notification

    user: {

        type:
        mongoose.Schema.Types.ObjectId,

        ref:
        "User",

        default:null

    },


    // Notification category

    type: {

        type:String,

        enum:[

            "system",

            "subscription",

            "security",

            "user",

            "organization"

        ],

        default:"system"

    },


    title: {

        type:String,

        required:true,

        trim:true

    },


    message: {

        type:String,

        required:true,

        trim:true

    },


    isRead: {

        type:Boolean,

        default:false

    },


    readAt: {

        type:Date,

        default:null

    },


        createdBy: {

        type:
        mongoose.Schema.Types.ObjectId,

        ref:
        "User",

        default:null

    },


    // Used to prevent duplicate system notifications
    // Example: one expiry notification per subscription

    referenceId: {

        type:
        mongoose.Schema.Types.ObjectId,

        default:null

    },


    isDeleted: {

        type:Boolean,

        default:false

    }


},

{

    timestamps:true

}

);



// Notification query optimization

NotificationSchema.index({

    organization:1,

    user:1,

    type:1,

    createdAt:-1

});


// Duplicate prevention lookup

NotificationSchema.index({

    organization:1,

    user:1,

    type:1,

    referenceId:1

});



module.exports =
mongoose.model(
    "Notification",
    NotificationSchema
);