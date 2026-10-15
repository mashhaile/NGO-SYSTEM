const mongoose = require("mongoose");


const counterSchema = new mongoose.Schema({

    organization:{

        type:mongoose.Schema.Types.ObjectId,

        ref:"Organization",

        required:true

    },


    module:{

        type:String,

        required:true

    },


    sequence:{

        type:Number,

        default:0

    }


});



counterSchema.index(

    {
        organization:1,
        module:1
    },

    {
        unique:true
    }

);



module.exports =
mongoose.model(
    "Counter",
    counterSchema
);