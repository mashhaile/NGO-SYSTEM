const mongoose = require("mongoose");

const attendanceSchema = new mongoose.Schema(
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
    // Activity Hierarchy
    // =====================================

    activityRun:{

        type:mongoose.Schema.Types.ObjectId,
        ref:"ActivityRun",
        required:true,
        index:true

    },



    project:{

        type:mongoose.Schema.Types.ObjectId,
        ref:"Project",
        required:true,
        index:true

    },



    program:{

        type:mongoose.Schema.Types.ObjectId,
        ref:"Program",
        required:true,
        index:true

    },



    // =====================================
    // Attendance Session
    // =====================================

    sessionTitle:{

        type:String,
        required:true,
        trim:true

    },



    sessionNumber:{

        type:Number,
        default:null

    },



    sessionDate:{

        type:Date,
        required:true,
        index:true

    },



    notes:{

        type:String,
        default:null,
        trim:true

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
        default:false,
        index:true

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
// Prevent duplicate session number
// =====================================

attendanceSchema.index(
{
    organization:1,
    activityRun:1,
    sessionNumber:1
},
{
    unique:true,
    partialFilterExpression:{
        sessionNumber:{
            $type:"number"
        }
    }
});



// =====================================
// Reporting Indexes
// =====================================

attendanceSchema.index({

    organization:1,
    activityRun:1,
    isDeleted:1

});



attendanceSchema.index({

    organization:1,
    project:1,
    sessionDate:-1

});



attendanceSchema.index({

    organization:1,
    program:1,
    sessionDate:-1

});



attendanceSchema.index({

    organization:1,
    sessionDate:-1

});



// dates that must make sense (see plugins/dateRules)
attendanceSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This attendance session",
        labels: { sessionDate: "session date" },
        rules: [
            { inside: { model: "ActivityRun", ref: "activityRun", fields: ["sessionDate"], title: "activity run" } }
        ]
    }
);


// dated inside its project (see plugins/insideProjectDates)
attendanceSchema.plugin(
    require("./plugins/insideProjectDates"),
    { dates: ["sessionDate"], what: "This attendance session", labels: { sessionDate: "session date" } }
);


module.exports = mongoose.model(
    "Attendance",
    attendanceSchema
);