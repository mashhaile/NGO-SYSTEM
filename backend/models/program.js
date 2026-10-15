const mongoose = require("mongoose");

const programSchema = new mongoose.Schema(

{

    // =====================================
    // Tenant Isolation
    // =====================================

    organization:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"Organization",

        required:true,

        index:true

    },



    // =====================================
    // Program Information
    // =====================================

    programCode:{

        type:String,

        required:true,

        trim:true

    },



    name:{

        type:String,

        required:true,

        trim:true

    },



    category:{

        type:String,

        default:null

    },



    description:{

        type:String,

        default:null

    },



    budget:{

        type:Number,

        default:0

    },



    targetBeneficiaries:{

        type:Number,

        default:0

    },



    startDate:{

        type:Date,

        required:true

    },



    endDate:{

        type:Date,

        default:null

    },



    status:{

        type:String,

        enum:[

            "Planned",

            "Active",

            "Completed",

            "Suspended",

            "Cancelled"

        ],

        default:"Planned"

    },



    customFields:[

        {

            fieldId:{

                type:mongoose.Schema.Types.ObjectId,

                ref:"CustomField"

            },

            key:String,

            label:String,

            type:String,

            value:mongoose.Schema.Types.Mixed

        }

    ],



    // =====================================
    // Audit
    // =====================================

    createdBy:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"User",

        default:null

    },



    updatedBy:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"User",

        default:null

    },



    // =====================================
    // Soft Delete
    // =====================================

    isDeleted:{

        type:Boolean,

        default:false

    },



    deletedAt:{

        type:Date,

        default:null

    },



    deletedBy:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"User",

        default:null

    }

},

{

    timestamps:true

}

);



// =====================================
// Unique Program Code Per Organization
// =====================================

programSchema.index(

{

    organization:1,

    programCode:1

},

{

    unique:true

}

);



// =====================================
// Tenant Queries
// =====================================

programSchema.index({

    organization:1,

    isDeleted:1

});



// =====================================
// Dashboard
// =====================================

programSchema.index({

    organization:1,

    status:1

});



// =====================================
// Reporting
// =====================================

programSchema.index({

    createdAt:-1

});

programSchema.index({

    organization:1,

    name:1

});
module.exports = mongoose.model(

    "Program",

    programSchema

);