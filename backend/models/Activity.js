const mongoose = require("mongoose");


const activitySchema = new mongoose.Schema(

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
    // Project Relation
    // =====================================

    project:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"Project",

        required:true,

        index:true

    },


    // =====================================
    // Activity Information
    // =====================================

    activityCode:{

        type:String,

        trim:true,

        default:null

    },


    name:{

        type:String,

        required:true,

        trim:true

    },


    activityType:{

        type:String,

        enum:[

            "Training",
            "Workshop",
            "Seminar",
            "Meeting",
            "Conference",
            "Awareness Campaign",
            "Field Visit",
            "Monitoring Visit",
            "Assessment",
            "Distribution",
            "Community Dialogue",
            "Other"

        ],

        default:"Training"

    },


    participantSource:{

        type:String,

        enum:[

            "Enrolled Beneficiaries",
            "Staff",
            "Board Members",
            "Volunteers",
            "Partners",
            "External Participants",
            "Mixed"

        ],

        default:"Enrolled Beneficiaries"

    },


    targetGroups:[{

        type:String,

        enum:[

            "Women",
            "Men",
            "Youth",
            "Children",
            "Persons with Disabilities",
            "Farmers",
            "Entrepreneurs",
            "Students",
            "Teachers",
            "Health Workers",
            "Community Leaders",
            "Staff",
            "Board Members",
            "Partners",
            "Government Officials",
            "General Public"

        ]

    }],


    description:{

        type:String,

        default:null

    },


    activityDate:{

        type:Date,

        required:true

    },


    location:{

        type:String,

        default:null

    },


    facilitator:{

        type:String,

        default:null

    },


    targetParticipants:{

        type:Number,

        default:0,

        min:0

    },


    status:{

        type:String,

        enum:[

            "Planned",
            "Ongoing",
            "Completed",
            "Cancelled"

        ],

        default:"Planned"

    },


    remarks:{

        type:String,

        default:null

    },


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
// Unique Activity Code Per Organization
// =====================================

activitySchema.index(

{

    organization:1,

    activityCode:1

},

{

    unique:true,

    sparse:true

}

);



// =====================================
// Tenant Queries
// =====================================

activitySchema.index({

    organization:1,

    isDeleted:1

});



// =====================================
// Project Activities
// =====================================

activitySchema.index({

    project:1,

    activityDate:-1

});



// =====================================
// Activity Type
// =====================================

activitySchema.index({

    organization:1,

    activityType:1

});



// =====================================
// Participant Source
// =====================================

activitySchema.index({

    organization:1,

    participantSource:1

});



// =====================================
// Reporting
// =====================================

activitySchema.index({

    organization:1,

    status:1,

    activityDate:-1

});



module.exports = mongoose.model(

    "Activity",

    activitySchema

);