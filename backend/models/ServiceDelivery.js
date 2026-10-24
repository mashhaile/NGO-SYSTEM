const mongoose = require("mongoose");

const {
    SERVICE_DELIVERY_STATUSES,
    DEFAULT_SERVICE_DELIVERY_STATUS
} = require("../constants/serviceDeliveryStatus");



// ==========================================
// DETAIL ITEM SCHEMA
// Additional breakdown of a delivered
// service item.
//
// IMPORTANT:
// - name is plain text.
// - It is NOT a Lookup.
// - unit uses the existing ServiceDelivery
//   Unit Lookup.
// ==========================================

const detailItemSchema = new mongoose.Schema(
{
    // ======================================
    // Detail Item Name
    // ======================================
    //
    // Examples:
    // - Mathematics textbook
    // - Exercise book
    // - School uniform
    // - Training session
    //
    // This is intentionally plain text.
    // There is NO Lookup for this field.
    // ======================================

    name: {

        type: String,

        default: "",

        trim: true,

        maxlength: 255

    },


    // ======================================
    // Detail Quantity
    //
    // Above 0. Whole numbers for countable
    // units (Piece, Set, ...); decimals for
    // weights and volumes (Kg, Liter, Meter).
    // The service checks which.
    // ======================================

    quantity: {

        type: Number,

        required: true,

        default: 1,

        min: 0.001

    },


    // ======================================
    // Detail Unit
    //
    // Uses the same existing Lookup system
    // as the parent service item.
    //
    // Examples:
    // Piece
    // Person
    // Household
    // Session
    // Kg
    // Liter
    // etc.
    // ======================================

    unit: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        default: null

    },
    // ======================================
    // ALLOCATION UNIT
    //
    // Defines the unit in which beneficiary
    // allocations are recorded.
    //
    // IMPORTANT:
    //
    // This is an organization-managed Lookup.
    // It must belong to the same organization
    // as the Service Delivery.
    //
    // It may be the same as the delivery unit
    // or a different physical unit configured
    // for allocation.
    //
    // Example:
    //
    // Delivery:
    //     1 Box
    //
    // Allocation:
    //     Pack
    //
    // The actual conversion factor is stored
    // separately in allocationConversionFactor.
    // ======================================

    allocationUnit: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        default: null

    },


    // ======================================
    // ALLOCATION CONVERSION FACTOR
    //
    // Defines how many allocation units are
    // contained in one delivery unit.
    //
    // Example:
    //
    // Delivery:
    //     1 Box
    //
    // Allocation Unit:
    //     Pack
    //
    // Conversion Factor:
    //     20
    //
    // Therefore:
    //
    // 1 Box = 20 Packs
    //
    // IMPORTANT:
    //
    // This value is configuration for this
    // particular service item.
    //
    // It is NOT a global conversion.
    // It must NEVER be inferred from the unit
    // name, unit code, or detail items.
    // ======================================

    allocationConversionFactor: {

        type: Number,

        default: 1,

        min: 0.000001

    },

    // ======================================
    // Detail Unit Cost
    // ======================================

    unitCost: {

        type: Number,

        default: 0,

        min: 0

    },


    // ======================================
    // Detail Total Cost
    //
    // Automatically calculated:
    //
    // quantity × unitCost
    // ======================================

    // What a detail item cost in its item's currency (USD, EUR),
    // when that is not ETB; unitCost / totalCost are in ETB
    originalUnitCost: {
        type: Number,
        default: null
    },

    totalCost: {

        type: Number,

        default: 0,

        min: 0

    }

},
{

    // Detail lines also receive their own
    // ObjectId so they can be preserved during
    // edit operations.
    _id: true

}
);



// ==========================================
// SERVICE ITEM SCHEMA
// Goods / Services delivered
// ==========================================

const serviceItemSchema = new mongoose.Schema(
{
    serviceCategory: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        required: true

    },


    serviceType: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        required: true

    },


    // Above 0; whole numbers unless the unit is a
    // weight or volume (checked by the service).
    quantity: {

        type: Number,

        required: true,

        default: 1,

        min: 0.001

    },


    // ======================================
    // ALLOCATION BEHAVIOR
    //
    // Taken from the service type when the delivery
    // is saved, and kept with it, so the delivery is
    // always read the way it was checked:
    //
    //   CONSUMPTION   the quantity is shared out
    //                 (10 kits for 10 people)
    //   PARTICIPATION each person takes part in all
    //                 of it (a 3-session training)
    // ======================================

    allocationBehavior: {

        type: String,

        enum: ["CONSUMPTION", "PARTICIPATION", null],

        default: null

    },


    // ======================================
    // UNIT
    //
    // Organization-managed Lookup value.
    //
    // Examples:
    // Piece
    // Person
    // Household
    // Session
    // Kg
    // Liter
    // etc.
    // ======================================

    unit: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        required: true

    },


    unitCost: {

        type: Number,

        default: 0,

        min: 0

    },


    // The item's currency (ETB by default). In another one
    // (USD, EUR) the price as entered is originalUnitCost and
    // unitCost / totalCost are in ETB at exchangeRate
    // (1 unit of the currency = exchangeRate ETB)
    currency: {
        type: String,
        uppercase: true,
        trim: true,
        default: "ETB",
        match: /^[A-Z]{3}$/
    },

    exchangeRate: {
        type: Number,
        default: 1,
        min: 0
    },

    originalUnitCost: {
        type: Number,
        default: null
    },

    originalTotal: {
        type: Number,
        default: null
    },

    totalCost: {

        type: Number,

        default: 0,

        min: 0

    },


    // ======================================
    // DONOR
    //
    // Donor responsible for / associated
    // with this specific service item.
    //
    // This is a dedicated Donor resource,
    // NOT a Lookup.
    // ======================================

    donor: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Donor",

        default: null

    },


    // ======================================
    // DONATION
    //
    // Donation associated with this specific
    // service item.
    //
    // This is a dedicated Donation resource,
    // NOT a Lookup.
    // ======================================

    donation: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Donation",
        default: null
    },

    // Bought with this expense (the kits bought with
    // EXP-000123, then given out): the expense already uses
    // the donation's money, so this item does not use it again
    paidByExpense: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Expense",
        default: null
    },

    // Expenses the user said this item was NOT bought with
    // (no more "was it bought with...?" suggestions for them)
    separateFromExpenses: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Expense"
    }],

    // ======================================
    // DETAIL ITEMS
    //
    // Optional breakdown of the actual
    // delivered service item.
    //
    // Detail item names are plain text.
    // They are NOT Lookup values.
    // ======================================

    detailItems: {

        type: [detailItemSchema],

        default: []

    },


    remarks: {

        type: String,

        default: "",

        trim: true

    }

},
{

    /*
     * IMPORTANT:
     *
     * Each service item has its own ObjectId.
     *
     * Beneficiary allocation records reference
     * the exact service item instead of relying
     * on an array index.
     */

    _id: true

}
);



// ==========================================
// SERVICE DELIVERY SCHEMA
// ==========================================

const serviceDeliverySchema = new mongoose.Schema(
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
    // Delivery Number
    // ======================================

    deliveryNumber: {

        type: String,

        required: true,

        trim: true

    },


    // ======================================
    // Recipient Type
    //
    // Defines WHO receives the service.
    //
    // Individual:
    //     One or more identified beneficiaries.
    //
    // Household:
    //     Support intended for a household/family.
    //
    // Group / Community:
    //     Collective support delivered to an
    //     identified group or community.
    //
    // Institution:
    //     Support delivered to an identified
    //     institution.
    // ======================================

    recipientType: {

        type: String,

        enum: [

            "Individual",

            "Household",

            "Group / Community",

            "Institution"

        ],

        default: "Individual",

        required: true

    },


    // ======================================
    // Recipient Name
    //
    // Identifies the non-individual recipient
    // when the delivery is made to a:
    //
    // - Group / Community
    // - Institution
    //
    // IMPORTANT:
    //
    // This is separate from beneficiary
    // associations.
    //
    // A Group / Community or Institution can
    // therefore be identified even when there
    // are zero individual beneficiaries.
    //
    // Example:
    //
    // recipientType:
    //     Group / Community
    //
    // recipientName:
    //     Debre Birhan Youth Community
    //
    // Or:
    //
    // recipientType:
    //     Institution
    //
    // recipientName:
    //     Debre Birhan Primary School
    //
    // Validation of when this field is required
    // is handled by the service/validator layer.
    // ======================================

    recipientName: {

        type: String,

        default: "",

        trim: true,

        maxlength: 255

    },


    // ======================================
    // Allocation Method
    //
    // Defines HOW the delivery cost/value is
    // attributed to recipients/beneficiaries.
    //
    // Individual:
    //     Cost/value is attributable to specific
    //     beneficiaries.
    //
    // Shared:
    //     One shared service/cost benefits multiple
    //     beneficiaries without automatically
    //     multiplying the total cost.
    //
    // Group:
    //     Cost is attributable to the identified
    //     group/community rather than individually.
    //
    // Unallocated:
    //     Actual delivery cost is recorded but no
    //     beneficiary-level financial allocation
    //     is declared.
    // ======================================

    allocationMethod: {

        type: String,

        enum: [

            "Individual",

            "Shared",

            "Group",

            "Unallocated"

        ],

        default: "Individual",

        required: true

    },


    // ======================================
    // Legacy Beneficiary
    //
    // IMPORTANT:
    //
    // New beneficiary relationships are handled
    // through ServiceDeliveryBeneficiary.
    //
    // This field is retained temporarily for
    // backward compatibility with existing data.
    // ======================================

    beneficiary: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Beneficiary",

        default: null

    },


    // ======================================
    // Enrollment Relationship
    // ======================================

    enrollment: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Enrollment",

        default: null

    },


    // ======================================
    // Program
    // ======================================

    program: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Program",

        required: true

    },


    // ======================================
    // Project
    // ======================================

    project: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Project",

        default: null

    },


    // ======================================
    // Activity
    // ======================================

    activity: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Activity",

        default: null

    },


    // ======================================
    // Activity Run
    //
    // Actual implementation event.
    // ======================================

    activityRun: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "ActivityRun",

        default: null

    },


    // ======================================
    // Funding Source
    // ======================================

    fundingSource: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Lookup",

        default: null

    },


    // ======================================
    // Donation Source
    //
    // LEGACY / BACKWARD COMPATIBILITY
    //
    // New item-level donation relationships
    // are stored inside:
    //
    // items[].donation
    //
    // This parent-level field is retained so
    // existing records continue to work.
    // ======================================

    donation: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "Donation",

        default: null

    },


    // ======================================
    // Delivered Items
    //
    // These represent the ACTUAL goods/services
    // delivered and their actual financial cost.
    //
    // Beneficiary distribution is NOT stored here.
    // It is stored in ServiceDeliveryBeneficiary.
    // ======================================

    items: [

        serviceItemSchema

    ],


    // ======================================
    // Total Delivery Amount
    //
    // Automatically calculated from service items.
    //
    // This represents ACTUAL DELIVERY COST.
    //
    // It must not automatically be multiplied by
    // the number of beneficiaries.
    // ======================================

    totalAmount: {

        type: Number,

        default: 0,

        min: 0

    },


    // ======================================
    // Service Delivery Date
    // ======================================

    deliveryDate: {

        type: Date,

        required: true,

        default: Date.now

    },


    // ======================================
    // Delivery Location
    // ======================================
    //
    // region / zone / woreda come from the official
    // AdminArea list (with P-codes).
    // deliveryLocation is the venue / site text.
    //
    // ======================================

    region: {

        type: String,

        default: "",

        trim: true

    },

    regionCode: {

        type: String,

        default: "",

        trim: true

    },

    zone: {

        type: String,

        default: "",

        trim: true

    },

    zoneCode: {

        type: String,

        default: "",

        trim: true

    },

    woreda: {

        type: String,

        default: "",

        trim: true

    },

    woredaCode: {

        type: String,

        default: "",

        trim: true

    },

    deliveryLocation: {

        type: String,

        default: "",

        trim: true

    },


    // ======================================
    // Delivery Status
    // ======================================

    // Delivered or Cancelled
    // (see constants/serviceDeliveryStatus.js)

    status: {

        type: String,

        enum: SERVICE_DELIVERY_STATUSES,

        default: DEFAULT_SERVICE_DELIVERY_STATUS

    },


    // ======================================
    // Person Responsible
    // ======================================

    deliveredBy: {

        type: mongoose.Schema.Types.ObjectId,

        ref: "User",

        default: null

    },


    // ======================================
    // Documents / Attachments
    // ======================================

    documents: [

        {

            documentType: {

                type: String,

                default: "",

                trim: true

            },


            fileName: {

                type: String,

                default: "",

                trim: true

            },


            fileUrl: {

                type: String,

                default: "",

                trim: true

            },


            uploadedAt: {

                type: Date,

                default: Date.now

            }

        }

    ],


    // ======================================
    // Audit Tracking
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

    },


    // ======================================
    // Soft Delete
    // ======================================

    isDeleted: {

        type: Boolean,

        default: false

    },


    deletedAt: {

        type: Date,

        default: null

    },


    deletedBy: {

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
// AUTO CALCULATE ITEM TOTALS
// ==========================================
//
// DETAIL ITEM:
//     quantity × unitCost = totalCost
//
// PARENT SERVICE ITEM:
//     quantity × unitCost = totalCost
//
// DELIVERY:
//     sum(parent item totalCost) = totalAmount
//
// IMPORTANT:
//
// Detail-item totals are informational/
// breakdown totals.
//
// They DO NOT replace the authoritative
// parent service-item quantity/unit/unitCost.
//
// Beneficiary allocation continues to reference
// the parent service item's _id.
//
// ==========================================

serviceDeliverySchema.pre(
    "save",
    function () {

        if (
            !Array.isArray(
                this.items
            )
        ) {

            this.items = [];

        }


        this.items.forEach(
            (item) => {

                // ----------------------------------
                // Calculate detail item totals
                // ----------------------------------

                if (
                    !Array.isArray(
                        item.detailItems
                    )
                ) {

                    item.detailItems = [];

                }


                item.detailItems.forEach(
                    (detailItem) => {

                        detailItem.totalCost =

                            Number(
                                detailItem.quantity || 0
                            ) *

                            Number(
                                detailItem.unitCost || 0
                            );

                    }
                );


                // ----------------------------------
                // Calculate parent service item total
                // ----------------------------------

                item.totalCost =

                    Number(
                        item.quantity || 0
                    ) *

                    Number(
                        item.unitCost || 0
                    );

            }
        );


        // --------------------------------------
        // Calculate total delivery amount
        //
        // IMPORTANT:
        // Sum parent service item totals.
        // Do NOT sum detail item totals here.
        // --------------------------------------

        this.totalAmount =

            this.items.reduce(
                (
                    sum,
                    item
                ) => {

                    return (

                        sum +

                        Number(
                            item.totalCost || 0
                        )

                    );

                },
                0
            );

    }
);



// ==========================================
// INDEXES
// ==========================================

// ------------------------------------------
// Tenant / Soft Delete
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    isDeleted: 1

});



// ------------------------------------------
// Unique Delivery Number per Organization
// ------------------------------------------

serviceDeliverySchema.index(

    {

        organization: 1,

        deliveryNumber: 1

    },

    {

        unique: true

    }

);



// ------------------------------------------
// Legacy Beneficiary History
// ------------------------------------------
//
// Retained because older records may still use
// ServiceDelivery.beneficiary.
//

serviceDeliverySchema.index({

    organization: 1,

    beneficiary: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Enrollment Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    enrollment: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Program Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    program: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Project Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    project: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Activity Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    activity: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Activity Run Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    activityRun: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Total Amount Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    totalAmount: -1

});



// ------------------------------------------
// Delivery Date Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Recipient Type Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    recipientType: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Recipient Name Reporting
// ------------------------------------------
//
// Supports reporting/searching by identified
// group, community, or institution.
//

serviceDeliverySchema.index({

    organization: 1,

    recipientName: 1,

    deliveryDate: -1

});



// ------------------------------------------
// Allocation Method Reporting
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    allocationMethod: 1,

    deliveryDate: -1

});



// ------------------------------------------
// SERVICE CATEGORY REPORTING
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    "items.serviceCategory": 1

});



// ------------------------------------------
// SERVICE TYPE REPORTING
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    "items.serviceType": 1

});



// ------------------------------------------
// UNIT REPORTING
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    "items.unit": 1

});



// ------------------------------------------
// DONOR REPORTING
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    "items.donor": 1

});



// ------------------------------------------
// DONATION REPORTING
// ------------------------------------------

serviceDeliverySchema.index({

    organization: 1,

    "items.donation": 1

});



// ------------------------------------------
// DETAIL ITEM NAME REPORTING
// ------------------------------------------
//
// Detail item names are free text, not Lookup
// values. This index supports searching/filtering
// when needed.
//

serviceDeliverySchema.index({

    organization: 1,

    "items.detailItems.name": 1

});



// ==========================================
// MODEL
// ==========================================

// dated inside its project (see plugins/insideProjectDates)
serviceDeliverySchema.plugin(
    require("./plugins/insideProjectDates"),
    { dates: ["deliveryDate"], what: "This service delivery", labels: { deliveryDate: "delivery date" } }
);


module.exports = mongoose.model(

    "ServiceDelivery",

    serviceDeliverySchema

);
