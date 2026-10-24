const mongoose = require("mongoose");


const donationSchema = new mongoose.Schema(
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
// Donor
// =====================================

donor:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Donor",

    required:true,

    index:true

},


// =====================================
// Program / Project / Activity / Run
// =====================================

program:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Program",

    default:null,

    index:true

},


project:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Project",

    default:null,

    index:true

},


// =====================================
// Activity
// =====================================

activity:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"Activity",

    default:null,

    index:true

},


// =====================================
// Activity Run
// =====================================

activityRun:{

    type:mongoose.Schema.Types.ObjectId,

    ref:"ActivityRun",

    default:null,

    index:true

},


// =====================================
// Donation Number
// =====================================

donationCode:{

    type:String,

    required:true,

    trim:true,

    uppercase:true,

    index:true

},


// =====================================
// Donation Information
// =====================================

title:{

    type:String,

    required:true,

    trim:true

},


amount:{

    type:Number,

    required:true,

    min:0

},


// A donation in another currency (USD, EUR): what 1 unit
// was worth in ETB on the day it was received. The donor's
// figures stay in the donation's currency; ETB totals of the
// organization use this rate for what was received
receivedRate:{
    type:Number,
    default:null,
    min:0
},

receivedRateDate:{
    type:Date,
    default:null
},

currency:{
    type:String,
    default:"USD",

    uppercase:true,

    trim:true

},


donationDate:{

    type:Date,

    required:true

},


financialYear:{

    type:String,

    default:null,

    index:true

},


// =====================================
// Funding Classification
// =====================================

fundingSource:{

    type:String,

    enum:[

        "Grant",

        "Donation",

        "Government Funding",

        "Corporate CSR",

        "Internal",

        "Other"

    ],

    default:"Donation"

},


fundingRestriction:{

    type:String,

    enum:[

        "Restricted",

        "Unrestricted"

    ],

    default:"Unrestricted"

},


// =====================================
// Donation Type
// =====================================

donationType:{

    type:String,

    enum:[

        "Cash",

        "Bank Transfer",

        "Material",

        "Equipment",

        "Service",

        "Other"

    ],

    default:"Cash"

},


// =====================================
// Payment Status
// =====================================

// Bumped (in a transaction) by every charge to this
// donation, so two charges at the same moment cannot both
// use the last of it
chargeVersion:{
    type:Number,
    default:0
},

status:{

    type:String,

    enum:[

        "Pledged",

        "Received",

        "Cancelled"

    ],

    default:"Received",

    index:true

},


// =====================================
// Receipt Information
// =====================================

receiptNumber:{

    type:String,

    default:null

},


referenceNumber:{

    type:String,

    default:null

},


description:{

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
// Unique Donation Code Per Organization
// =====================================

donationSchema.index(

{

    organization:1,

    donationCode:1

},

{

    unique:true

}

);


// =====================================
// Reporting Indexes
// =====================================

donationSchema.index({

    organization:1,

    donor:1

});


donationSchema.index({

    organization:1,

    program:1

});


donationSchema.index({

    organization:1,

    project:1

});


donationSchema.index({

    organization:1,

    activity:1

});


donationSchema.index({

    organization:1,

    activityRun:1

});


donationSchema.index({

    organization:1,

    status:1

});


donationSchema.index({

    organization:1,

    financialYear:1

});


donationSchema.index({

    organization:1,

    fundingSource:1

});


donationSchema.index({

    organization:1,

    donationDate:-1

});


donationSchema.index({

    organization:1,

    currency:1

});


donationSchema.index({

    organization:1,

    donor:1,

    donationDate:-1

});


donationSchema.index({

    organization:1,

    activity:1,

    donationDate:-1

});


donationSchema.index({

    organization:1,

    activityRun:1,

    donationDate:-1

});


// =====================================
// MODEL
// =====================================

// dates that must make sense (see plugins/dateRules)
donationSchema.plugin(
    require("./plugins/dateRules"),
    {
        what: "This donation",
        labels: { donationDate: "date" },
        rules: [
            { notFuture: "donationDate", watch: ["status"], when: (v) => v.status === "Received", because: "A donation still to come is Pledged." }
        ]
    }
);


module.exports =

    mongoose.models.Donation ||

    mongoose.model(

        "Donation",

        donationSchema

    );