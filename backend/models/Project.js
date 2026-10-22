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



// No budget field: a project's budget lives in the
// Budgets module (services/budgetFigures.js).



startDate:{

type:Date,

required:true

},



endDate:{

type:Date,

required:true

},



status:{

type:String,

enum:[

"Draft",

"Active",

"Completed",

"Cancelled"

],

default:"Draft"

},



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



module.exports =
mongoose.model(
"Project",
projectSchema
);