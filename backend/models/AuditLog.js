const mongoose = require("mongoose");


const auditLogSchema =
new mongoose.Schema({

    organizationId: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Organization",

        default: null

    },


    userId: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "User",

        default: null

    },


    action: {

        type: String,

        required: true,

        trim: true

    },


    module: {

        type: String,

        required: true,

        trim: true

    },


    entityType: {

        type: String,

        required: true,

        trim: true

    },


    entityId: {

        type: mongoose.Schema.Types.ObjectId,

        default: null

    },


    description: {

        type: String,

        trim: true

    },


    metadata: {

        type: mongoose.Schema.Types.Mixed,

        default: {}

    },
success: {

    type: Boolean,

    default: true

},



severity: {

    type: String,

    enum: [

        "info",

        "warning",

        "error",

        "critical"

    ],

    default: "info"

},

    ipAddress: {

        type: String,

        default: null

    },


    userAgent: {

        type: String,

        default: null

    },


    isDeleted: {

        type: Boolean,

        default: false

    }


},
{

    timestamps: true

});



// Indexes for faster searching

auditLogSchema.index({

    organizationId: 1,

    createdAt: -1

});


auditLogSchema.index({

    userId: 1,

    createdAt: -1

});


auditLogSchema.index({

    action: 1

});
auditLogSchema.index({

    module:1,

    createdAt:-1

});



module.exports =
mongoose.model(
    "AuditLog",
    auditLogSchema
);