const express = require("express");
const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const limitMiddleware = require("../middleware/LimitMiddleware");

const Beneficiary = require("../models/Beneficiary");

const {
    createBeneficiarySchema,
    updateBeneficiarySchema,
} = require("../validators/beneficiaryValidator");

const {
    createBeneficiaryController,
    getBeneficiariesController,
    getBeneficiaryByIdController,
    updateBeneficiaryController,
    deleteBeneficiaryController,
    getBeneficiaryLookupController
} = require("../controllers/beneficiaryController");

// =================================
// CREATE BENEFICIARY
// =================================

router.post(
    "/",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.create"),
    limitMiddleware("beneficiaries", Beneficiary),
    validate(createBeneficiarySchema),
    createBeneficiaryController
);
// =================================
// GET ALL BENEFICIARIES
// =================================

router.get(
    "/",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.read"),
    getBeneficiariesController
);


// =================================
// BENEFICIARY LOOKUP
// IMPORTANT: Must be before "/:id"
// =================================

router.get(
    "/lookup",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.read"),
    getBeneficiaryLookupController
);


// =================================
// GET BENEFICIARY BY ID
// =================================

router.get(
    "/:id",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.read"),
    getBeneficiaryByIdController
);

// =================================
// UPDATE BENEFICIARY
// =================================

router.put(
    "/:id",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.update"),
    validate(updateBeneficiarySchema),
    updateBeneficiaryController
);

// =================================
// DELETE BENEFICIARY
// =================================

router.delete(
    "/:id",
    authMiddleware,
    subscriptionMiddleware,
    authorize("beneficiary.delete"),
    deleteBeneficiaryController
);

module.exports = router;