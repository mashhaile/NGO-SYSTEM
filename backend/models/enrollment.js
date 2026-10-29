const mongoose = require("mongoose");


const enrollmentSchema = new mongoose.Schema(

{

organization:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Organization",

    required:true,

    index:true

},



// =====================================
// PROGRAM RELATIONSHIP
// =====================================

program:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Program",

    required:true,

    index:true

},




// =====================================
// PROJECT (or a phase of a project)
// =====================================
// People are enrolled in a project; the program comes from
// it. A project in phases enrolls in each phase (the same or
// new people); the main project shows its phases' people.
// Older enrollments made before projects may have none.

project:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Project",

    default:null,

    index:true

},




// =====================================
// BENEFICIARY
// =====================================

beneficiary:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Beneficiary",

    required:true,

    index:true

},





// =====================================
// ENROLLMENT INFORMATION
// =====================================

enrollmentDate:{

    type:Date,

    default:Date.now

},




status:{

    type:String,

    enum:[

        "Pending",

        "Active",

        "Completed",

        "Dropped",

        "Suspended"

    ],

    default:"Pending"

},




completionDate:{

    type:Date,

    default:null

},




exitReason:{

    type:String,

    default:null

},





remarks:{

    type:String,

    default:null

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

}

);





// Prevent duplicate enrollment
// Same beneficiary cannot enroll twice in the same project
// (or phase); they can be in several projects of a program.
// Older enrollments without a project: once per program.
// (The older unique index per program is dropped by
// scripts/migrateEnrollmentsToProjects.js.)

enrollmentSchema.index(

{

organization:1,

program:1,

project:1,

beneficiary:1,

isDeleted:1

},

{

unique:true

}

);





enrollmentSchema.index({

organization:1,

program:1,

createdAt:-1

});





// dates that must make sense (see plugins/dateRules)
enrollmentSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This enrollment",
        labels: { enrollmentDate: "enrollment date", completionDate: "completion date" },
        rules: [
            { order: ["enrollmentDate", "completionDate"] },
            { inside: { model: "Program", ref: "program", fields: ["enrollmentDate"], title: "program" } },
            { inside: { model: "Project", ref: "project", fields: ["enrollmentDate"], title: "project" } },
            { notFuture: "completionDate", because: "Record the completion when it happens." },
            {
                fields: ["beneficiary", "enrollmentDate"],
                check: async (v) => {
                    if (!v.beneficiary || !v.enrollmentDate) return null;
                    const person = await require("mongoose").model("Beneficiary").findById(v.beneficiary).select("dateOfBirth").lean();
                    return person?.dateOfBirth && new Date(v.enrollmentDate) < new Date(person.dateOfBirth)
                        ? "The enrollment date is before the person's date of birth."
                        : null;
                }
            }
        ]
    }
);


// what the status of its parents allows (see plugins/statusRules)
enrollmentSchema.plugin(
    require("./plugins/statusRules"),
    { what: "This enrollment", parents: [{ ref: "program", model: "Program", label: "program", kind: "plan" }, { ref: "project", model: "Project", label: "project", kind: "plan" }], inactive: [{ ref: "beneficiary", model: "Beneficiary", label: "beneficiary" }] }
);


module.exports =
    mongoose.models.Enrollment ||
    mongoose.model(
        "Enrollment",
        enrollmentSchema
    );