const mongoose = require("mongoose");


const ActivityRunSchema = new mongoose.Schema(
{

organization:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"Organization",
    required:true,
    index:true
},



// Parent Activity

activity:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"Activity",
    required:true,
    index:true
},



// Added for reporting

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



runCode:{
    type:String,
    required:true
},



name:{
    type:String,
    required:true,
    trim:true
},



startDate:{
    type:Date,
    required:true
},



endDate:{
    type:Date,
    default:null
},



// Region / Zone / Woreda with official P-codes
// (AdminArea). "location" holds the venue / site.

region:{
    type:String,
    default:null,
    trim:true
},

regionCode:{
    type:String,
    default:null,
    trim:true
},

zone:{
    type:String,
    default:null,
    trim:true
},

zoneCode:{
    type:String,
    default:null,
    trim:true
},

woreda:{
    type:String,
    default:null,
    trim:true
},

woredaCode:{
    type:String,
    default:null,
    trim:true
},


location:{
    type:String,
    default:null
},



trainer:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"User",
    default:null
},



targetGroup:{
    type:String,
    default:null
},



status:{
    type:String,
    enum:[
        "Planned",
        "Active",
        "Completed",
        "Cancelled"
    ],
    default:"Planned"
},



notes:{
    type:String,
    default:null
},



createdBy:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"User"
},



updatedBy:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"User"
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
    ref:"User"
}


},
{
timestamps:true
});





ActivityRunSchema.index(
{
organization:1,
runCode:1
},
{
unique:true
});



ActivityRunSchema.index(
{
organization:1,
activity:1
});
ActivityRunSchema.index(
{
    organization:1,
    project:1,
    createdAt:-1
});


ActivityRunSchema.index(
{
    organization:1,
    program:1,
    createdAt:-1
});

// dates that must make sense (see plugins/dateRules)
ActivityRunSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This activity run",
        rules: [
            { order: ["startDate", "endDate"] },
        {
            fields: ["startDate", "endDate"],
            check: async (v) => {
                if (!v._id || !v.startDate) return null;
                const mongoose = require("mongoose");
                const start = new Date(v.startDate);
                const end = v.endDate ? new Date(new Date(v.endDate).getTime() + 24 * 60 * 60 * 1000 - 1) : null;
                for (const [model, ref, field, label] of [["Attendance","activityRun","sessionDate","attendance session(s)"]]) {
                    const outside = [{ [field]: { $lt: start } }];
                    if (end) outside.push({ [field]: { $gt: end } });
                    const count = await mongoose.model(model).countDocuments({ [ref]: v._id, isDeleted: { $ne: true }, $or: outside });
                    if (count) return `${count} ${label} of this activity run ${count === 1 ? "is" : "are"} dated outside these dates. Move ${count === 1 ? "it" : "them"} first, or keep the activity run's dates around ${count === 1 ? "it" : "them"}.`;
                }
                return null;
            }
        }
        ]
    }
);


// dated inside its project (see plugins/insideProjectDates)
ActivityRunSchema.plugin(
    require("./plugins/insideProjectDates"),
    { dates: ["startDate", "endDate"], what: "This activity run", labels: { startDate: "start date", endDate: "end date" } }
);


module.exports =
mongoose.model(
"ActivityRun",
ActivityRunSchema
);