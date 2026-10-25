const { workStatusField } = require("../constants/workStatus");
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



    // No budget field: a program's budget lives in the
    // Budgets module (services/budgetFigures.js).

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



    // Planned / Active / Suspended / Completed / Cancelled (constants/workStatus.js)
    status: workStatusField(),



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
// dates that must make sense (see plugins/dateRules)
programSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This program",
        rules: [
            { order: ["startDate", "endDate"] },
        {
            fields: ["startDate", "endDate"],
            check: async (v) => {
                if (!v._id || !v.startDate) return null;
                const mongoose = require("mongoose");
                const start = new Date(v.startDate);
                const end = v.endDate ? new Date(new Date(v.endDate).getTime() + 24 * 60 * 60 * 1000 - 1) : null;
                for (const [model, ref, field, label] of [["Project","program","startDate","project(s)"],["Project","program","endDate","project(s)"],["Enrollment","program","enrollmentDate","enrollment(s)"]]) {
                    const outside = [{ [field]: { $lt: start } }];
                    if (end) outside.push({ [field]: { $gt: end } });
                    const count = await mongoose.model(model).countDocuments({ [ref]: v._id, isDeleted: { $ne: true }, $or: outside });
                    if (count) return `${count} ${label} of this program ${count === 1 ? "is" : "are"} dated outside these dates. Move ${count === 1 ? "it" : "them"} first, or keep the program's dates around ${count === 1 ? "it" : "them"}.`;
                }
                return null;
            }
        }
        ]
    }
);


module.exports = mongoose.model(

    "Program",

    programSchema

);