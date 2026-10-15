const express = require("express");

const router = express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");

const authorize =
    require("../middleware/authorize");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const limitMiddleware =
    require("../middleware/LimitMiddleware");

const validate =
    require("../middleware/validate");


const Enterprise =
    require("../models/Enterprise");


const {
    createEnterpriseController,
    getEnterprisesController,
    getEnterpriseByIdController,
    updateEnterpriseController,
    deleteEnterpriseController,
    getEnterpriseLookupController,
    getEnterprisesByBeneficiaryController
} =
    require("../controllers/enterpriseController");


// =====================================================
// CREATE ENTERPRISE
// =====================================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.create"),

    limitMiddleware(
        "enterprises",
        Enterprise
    ),

    createEnterpriseController

);


// =====================================================
// GET ALL ENTERPRISES
// =====================================================

router.get(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterprisesController

);


// =====================================================
// ENTERPRISE LOOKUP
// IMPORTANT:
// MUST COME BEFORE /:id
// =====================================================

router.get(

    "/lookup",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterpriseLookupController

);


// =====================================================
// ENTERPRISES BY BENEFICIARY
// IMPORTANT:
// MUST COME BEFORE /:id
// =====================================================

router.get(

    "/beneficiary/:beneficiaryId",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterprisesByBeneficiaryController

);


// =====================================================
// GET ENTERPRISE BY ID
// =====================================================

router.get(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.read"),

    getEnterpriseByIdController

);


// =====================================================
// UPDATE ENTERPRISE
// =====================================================

router.put(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.update"),

    updateEnterpriseController

);


// =====================================================
// DELETE ENTERPRISE
// =====================================================

router.delete(

    "/:id",

    authMiddleware,

    subscriptionMiddleware,

    authorize("enterprise.delete"),

    deleteEnterpriseController

);


module.exports = router;