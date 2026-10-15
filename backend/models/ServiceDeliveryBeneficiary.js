const mongoose = require("mongoose");



// ==========================================
// BENEFICIARY SERVICE ITEM ALLOCATION
//
// Defines how much of a specific ServiceDelivery
// item was actually received/allocated to one
// beneficiary.
//
// Example:
//
// Beneficiary A
//     Uniform → quantity 2 → ETB 4,000
//
// Beneficiary B
//     Uniform → quantity 1 → ETB 2,000
//
// The service item itself remains on
// ServiceDelivery.items.
// ==========================================

const serviceDeliveryBeneficiaryAllocationSchema =
    new mongoose.Schema(

        {

            // ======================================
            // Service Item
            //
            // References the exact item inside
            // ServiceDelivery.items.
            // ======================================

            serviceItem: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
},

// ======================================
// Supporting Detail Item
//
// Optional reference to a specific
// supporting detail item inside the
// ServiceDelivery service item.
//
// Example:
// Service Item: Education Materials
// Detail Item: Exercise Book
// ======================================

detailItem: {
    type: mongoose.Schema.Types.ObjectId,
    default: null
},


            // ======================================
            // Beneficiary-Specific Quantity
            //
            // Example:
            //
            // Uniform:
            //     Student A = 2
            //     Student B = 1
            // ======================================

            quantity: {

                type: Number,

                default: 0,

                min: 0

            },


            // ======================================
            // Beneficiary Allocated Value
            //
            // This is the value intentionally
            // attributed to this beneficiary for
            // this specific service item.
            //
            // It is NOT the same as the overall
            // ServiceDelivery.totalAmount.
            // ======================================

            allocatedValue: {

                type: Number,

                default: 0,

                min: 0

            },


            // ======================================
            // Allocation Remarks
            // ======================================

            remarks: {

                type: String,

                default: "",

                trim: true

            }

        },

        {

            _id: true

        }

    );



// ==========================================
// SERVICE DELIVERY BENEFICIARY
//
// Links one Service Delivery Event to
// one Beneficiary.
//
// This document represents:
//
// "This beneficiary was involved in this
// service delivery."
//
// The allocations[] array represents:
//
// "This is exactly what this beneficiary
// received/was allocated from the delivery."
// ==========================================

const serviceDeliveryBeneficiarySchema =
    new mongoose.Schema(

        {

            // ======================================
            // Tenant Isolation
            // ======================================

            organization: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "Organization",

                required: true

            },


            // ======================================
            // Service Delivery
            // Parent Event
            // ======================================

            serviceDelivery: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "ServiceDelivery",

                required: true

            },


            // ======================================
            // Beneficiary
            // ======================================

            beneficiary: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "Beneficiary",

                required: true

            },


            // ======================================
            // Enrollment
            //
            // Optional beneficiary-specific
            // enrollment.
            // ======================================

            enrollment: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "Enrollment",

                default: null

            },


            // ======================================
            // Beneficiary-Specific Status
            // ======================================

            status: {

                type: String,

                enum: [

                    "Received",

                    "Participated",

                    "Missed",

                    "Referred",

                    "Pending"

                ],

                default: "Received"

            },


            // ======================================
            // Beneficiary-Specific Quantity
            //
            // Legacy/general quantity.
            //
            // New multi-item distributions should
            // normally use allocations[].quantity.
            //
            // Kept for compatibility with existing
            // records and simple one-item deliveries.
            // ======================================

            quantity: {

                type: Number,

                default: null,

                min: 0

            },


            // ======================================
            // Service Item Allocations
            //
            // Each allocation points to a specific
            // ServiceDelivery item.
            //
            // This allows one beneficiary to receive
            // different quantities of different items.
            // ======================================

            allocations: [

                serviceDeliveryBeneficiaryAllocationSchema

            ],


            // ======================================
            // Beneficiary-Specific Remarks
            // ======================================

            remarks: {

                type: String,

                default: "",

                trim: true

            },


            // ======================================
            // Audit
            // ======================================

            createdBy: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "User",

                default: null

            },


            updatedBy: {

                type: mongoose.Schema.Types.ObjectId,

                ref: "User",

                default: null

            }

        },

        {

            timestamps: true

        }

    );



// ==========================================
// PREVENT DUPLICATE BENEFICIARY
// IN SAME SERVICE DELIVERY
// ==========================================

serviceDeliveryBeneficiarySchema.index(

    {

        organization: 1,

        serviceDelivery: 1,

        beneficiary: 1

    },

    {

        unique: true

    }

);



// ==========================================
// BENEFICIARY HISTORY
// ==========================================

serviceDeliveryBeneficiarySchema.index({

    organization: 1,

    beneficiary: 1,

    createdAt: -1

});



// ==========================================
// SERVICE DELIVERY REPORTING
// ==========================================

serviceDeliveryBeneficiarySchema.index({

    organization: 1,

    serviceDelivery: 1

});



// ==========================================
// ENROLLMENT REPORTING
// ==========================================

serviceDeliveryBeneficiarySchema.index({

    organization: 1,

    enrollment: 1,

    createdAt: -1

});



// ==========================================
// ALLOCATION REPORTING
// ==========================================

serviceDeliveryBeneficiarySchema.index({

    organization: 1,

    "allocations.serviceItem": 1

});
// ==========================================
// DETAIL ITEM ALLOCATION REPORTING
// ==========================================

serviceDeliveryBeneficiarySchema.index({

    organization: 1,

    "allocations.detailItem": 1

});


// ==========================================
// MODEL
// ==========================================

module.exports = mongoose.model(

    "ServiceDeliveryBeneficiary",

    serviceDeliveryBeneficiarySchema

);