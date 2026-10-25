const express = require("express");

const authMiddleware = require("../middleware/authMiddleware");
const authorize = require("../middleware/authorize");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const controller = require("../controllers/roleController");

// =====================================================
// ROLES: the organization's custom roles (the built-in
// ones are listed with them, read-only)
// =====================================================

const router = express.Router();
const base = [authMiddleware, subscriptionMiddleware];

router.get("/", ...base, authorize("user.read"), controller.listRoles);
router.post("/", ...base, authorize("role.manage"), controller.createRole);
router.put("/:id", ...base, authorize("role.manage"), controller.updateRole);
router.delete("/:id", ...base, authorize("role.manage"), controller.deleteRole);

module.exports = router;
