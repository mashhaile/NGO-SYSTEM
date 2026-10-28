const { workStatusField } = require("../constants/workStatus");
const mongoose = require("mongoose");


const projectSchema = new mongoose.Schema(

{

organization:{

type:mongoose.Schema.Types.ObjectId,

ref:"Organization",

required:true,

index:true

},


program:{

type:mongoose.Schema.Types.ObjectId,

ref:"Program",

required:true,

index:true

},



projectCode:{

type:String,

trim:true,

default:null

},



name:{

type:String,

required:true,

trim:true

},



description:{

type:String,

default:null

},



donor:{

type:mongoose.Schema.Types.ObjectId,

ref:"Donor",

default:null

},



projectManager:{

type:mongoose.Schema.Types.ObjectId,

ref:"User",

default:null

},



// Development, Humanitarian, Emergency ... (the organization's
// own list: Lookups > Projects > Project Type). Optional; a
// phase takes its main project's type.
projectType:{
type:mongoose.Schema.Types.ObjectId,
ref:"Lookup",
default:null,
index:true
},



// No budget field: a project's budget lives in the
// Budgets module (services/budgetFigures.js).



// A phase of this main project (Phase 1, Phase 2 ...): a
// project of its own (budget, activities, reports), grouped
// under the main project. See services/projectPhases.js
parentProject:{
type:mongoose.Schema.Types.ObjectId,
ref:"Project",
default:null,
index:true
},

phaseNumber:{
type:Number,
default:null
},

startDate:{
type:Date,
required:true
},



endDate:{

type:Date,

required:true

},



// Planned / Active / Suspended / Completed / Cancelled (constants/workStatus.js)
status: workStatusField(),



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




// Unique Project Code per Organization

projectSchema.index(

{

organization:1,

projectCode:1

},

{

unique:true,

sparse:true

}

);



// Tenant queries

projectSchema.index({

organization:1,

isDeleted:1

});



// Program projects

projectSchema.index({

program:1,

startDate:-1

});



// dates that must make sense (see plugins/dateRules)
projectSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This project",
        rules: [
            { order: ["startDate", "endDate"] },
            { inside: { model: "Program", ref: "program", fields: ["startDate", "endDate"], title: "program" } },
        {
            fields: ["startDate", "endDate"],
            check: async (v) => {
                if (!v._id || !v.startDate) return null;
                const mongoose = require("mongoose");
                const start = new Date(v.startDate);
                const end = v.endDate ? new Date(new Date(v.endDate).getTime() + 24 * 60 * 60 * 1000 - 1) : null;
                for (const [model, ref, field, label] of [["Activity","project","activityDate","activity(ies)"],["ActivityRun","project","startDate","activity run(s)"],["ActivityRun","project","endDate","activity run(s)"],["ServiceDelivery","project","deliveryDate","service delivery(ies)"],["Attendance","project","sessionDate","attendance session(s)"],["TermsOfReference","project","startDate","TOR(s)"],["TermsOfReference","project","endDate","TOR(s)"]]) {
                    const outside = [{ [field]: { $lt: start } }];
                    if (end) outside.push({ [field]: { $gt: end } });
                    const count = await mongoose.model(model).countDocuments({ [ref]: v._id, isDeleted: { $ne: true }, $or: outside });
                    if (count) return `${count} ${label} of this project ${count === 1 ? "is" : "are"} dated outside these dates. Move ${count === 1 ? "it" : "them"} first, or keep the project's dates around ${count === 1 ? "it" : "them"}.`;
                }
                return null;
            }
        }
        ]
    }
);


// what the status of its parents allows (see plugins/statusRules)
projectSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This project", parents: [{ ref: "program", model: "Program", label: "program", kind: "plan" }, { ref: "parentProject", model: "Project", label: "main project", kind: "plan" }] }
);


module.exports =
mongoose.model(
"Project",
projectSchema
);