const express = require("express");


const router =
    express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");


const {
    getLocationsController
} = require("../controllers/locationController");



// =====================================================
// GET LOCATIONS (REGION / ZONE / WOREDA)
// =====================================================
//
// GET /locations?level=1
// GET /locations?level=2&parent=ET03
// GET /locations?level=3&parent=ET0301
//
// Shared reference data: any authenticated user.
//
// =====================================================

router.get(

    "/",

    authMiddleware,

    getLocationsController

);


module.exports = router;
