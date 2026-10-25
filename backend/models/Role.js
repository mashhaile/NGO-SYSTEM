const mongoose = require("mongoose");


// =====================================================
// CUSTOM ROLE
// =====================================================
//
// A role an organization defines for itself ("Program
// Manager", "M&E Officer", "Administrator"): a name and the
// permissions its users have. The built-in roles
// (constants/rolepermissions.js) stay as they are; a user
// with a custom role gets its permissions instead of those
// of their built-in role. See services/roleService.js.
//
// =====================================================

const roleSchema = new mongoose.Schema(
    {
        organization: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Organization",
            required: true,
            index: true
        },

        name: {
            type: String,
            required: true,
            trim: true,
            maxlength: 60
        },

        description: {
            type: String,
            trim: true,
            default: "",
            maxlength: 300
        },

        // permission codes ("budget.approve" ...), at most those
        // of the organization admin
        permissions: [{
            type: String,
            trim: true
        }],

        createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

        isDeleted: { type: Boolean, default: false },
        deletedAt: { type: Date, default: null }
    },
    {
        timestamps: true
    }
);

// one name per organization (deleted roles free their name)
roleSchema.index(
    { organization: 1, name: 1 },
    { unique: true, partialFilterExpression: { isDeleted: false }, collation: { locale: "en", strength: 2 } }
);


module.exports =
    mongoose.models.Role ||
    mongoose.model("Role", roleSchema);
