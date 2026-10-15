const mongoose = require("mongoose");



const customFieldSchema = new mongoose.Schema(

{

    // ============================
    // Tenant
    // ============================

    organization: {

        type: mongoose.Schema.Types.ObjectId,

        ref:"Organization",

        required:true

    },



    // ============================
    // Module
    // ============================

    module: {

    type: String,

    required: true,

    enum: [
        "Beneficiary",
        "Donor",
        "Program",
        "ServiceDelivery",
        "User",
        "Enterprise",
        "EnterpriseMember"
    ]

},


    // ============================
    // Form Section
    // ============================

    section:{

        type:String,

        default:"General",

        trim:true

    },



    // ============================
    // Field Information
    // ============================

    label: {

        type:String,

        required:true,

        trim:true

    },



    key: {

        type:String,

        required:true,

        trim:true,

        lowercase:true

    },



    // ============================
    // Field Types
    // ============================

    type: {

        type:String,

        required:true,

        enum:[

            "text",

            "number",

            "date",

            "select",

            "multi_select",

            "radio",

            "checkbox",

            "textarea",

            "email",

            "phone",

            "currency",

            "file",

            "location"

        ]

    },



    // ============================
    // Select / Radio Options
    // ============================

    options:[

        {

            label:String,

            value:String

        }

    ],



    // ============================
    // UI Settings
    // ============================

    placeholder:{

        type:String,

        default:null

    },



    defaultValue:{

        type:mongoose.Schema.Types.Mixed,

        default:null

    },



    // ============================
    // Required Field
    // ============================

    required:{

        type:Boolean,

        default:false

    },



    // ============================
    // Validation Rules
    // ============================

    validation:{


        minLength:{

            type:Number,

            default:null

        },


        maxLength:{

            type:Number,

            default:null

        },


        minValue:{

            type:Number,

            default:null

        },


        maxValue:{

            type:Number,

            default:null

        },


        pattern:{

            type:String,

            default:null

        }


    },



    // ============================
    // Display Order
    // ============================

    order:{


        type:Number,

        default:0

    },



    // ============================
    // Status
    // ============================

    active:{


        type:Boolean,

        default:true

    },



    // ============================
    // Audit
    // ============================

    createdBy:{


        type:mongoose.Schema.Types.ObjectId,

        ref:"User",

        default:null

    },



    updatedBy:{


        type:mongoose.Schema.Types.ObjectId,

        ref:"User",

        default:null

    }


},


{

    timestamps:true

}

);




// Prevent duplicate fields inside same organization/module

customFieldSchema.index(

    {

        organization:1,

        module:1,

        key:1

    },

    {

        unique:true

    }

);



module.exports = mongoose.model(

    "CustomField",

    customFieldSchema

);