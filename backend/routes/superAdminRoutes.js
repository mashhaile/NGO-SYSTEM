const express = require("express");

const router = express.Router();


const authMiddleware =
require("../middleware/authMiddleware");

const requireRole =
require("../middleware/roleMiddleware");


const {
    createOrganizationAdmin
}=require("../controllers/superAdminController");



router.post(
    "/organization-admin",
    authMiddleware,
    requireRole("super_admin"),
    createOrganizationAdmin
);


module.exports=router;