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
// Same beneficiary cannot enroll twice in same program

enrollmentSchema.index(

{

organization:1,

program:1,

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





module.exports =
    mongoose.models.Enrollment ||
    mongoose.model(
        "Enrollment",
        enrollmentSchema
    );