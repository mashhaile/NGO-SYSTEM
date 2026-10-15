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


const Beneficiary =
    require("../models/Beneficiary");


const {
    importBeneficiariesController,
    downloadBeneficiaryTemplate

} = require("../controllers/beneficiaryImportController");




// ==========================================
// IMPORT BENEFICIARIES
// ==========================================

router.post(

    "/",

    authMiddleware,

    subscriptionMiddleware,

    authorize("beneficiary.create"),

    limitMiddleware(
        "beneficiaries",
        Beneficiary
    ),

    importBeneficiariesController

);




// ==========================================
// DOWNLOAD TEMPLATE
// ==========================================

router.get(

    "/template",

    authMiddleware,

    subscriptionMiddleware,

    authorize("beneficiary.read"),

    downloadBeneficiaryTemplate

);



module.exports = router;