const express =
    require("express");

const router =
    express.Router();


const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");

const validate =
    require("../middleware/validate");


const {
    createTor,
    getTors,
    getTorById,
    updateTor,
    deleteTor,
    submitTor,
    approveTor,
    returnTor,
    createActivityFromTor,
    linkActivity,
    downloadTorPdf
} = require("../controllers/torController");


const {
    createTorSchema,
    updateTorSchema,
    returnTorSchema,
    approveTorSchema,
    linkActivitySchema
} = require("../validators/torValidator");



// =====================================================
// TERMS OF REFERENCE
// =====================================================
//
// GET    /tors                list (search, status, activity, project, page, limit)
// POST   /tors                create (Draft)
// GET    /tors/:id            details
// PUT    /tors/:id            edit (Draft / Returned only)
// DELETE /tors/:id            delete (Draft / Returned only)
// POST   /tors/:id/submit     Draft / Returned -> Submitted
// POST   /tors/:id/approve    Submitted -> Approved   (tor.approve)
// POST   /tors/:id/return     Submitted -> Returned   (tor.approve, comment required)
// POST   /tors/:id/create-activity  Approved TOR -> new Activity (tor.create_activity)
// POST   /tors/:id/link-activity    link an existing activity of the same project
// GET    /tors/:id/pdf        download PDF
//
// =====================================================

const base = [
    authMiddleware,
    subscriptionMiddleware
];


router.get(
    "/",
    ...base,
    authorize("tor.read"),
    getTors
);

router.post(
    "/",
    ...base,
    authorize("tor.create"),
    validate(createTorSchema),
    createTor
);

router.get(
    "/:id/pdf",
    ...base,
    authorize("tor.read"),
    downloadTorPdf
);

router.get(
    "/:id",
    ...base,
    authorize("tor.read"),
    getTorById
);

router.put(
    "/:id",
    ...base,
    authorize("tor.update"),
    validate(updateTorSchema),
    updateTor
);

router.delete(
    "/:id",
    ...base,
    authorize("tor.delete"),
    deleteTor
);

router.post(
    "/:id/submit",
    ...base,
    authorize("tor.update"),
    submitTor
);

router.post(
    "/:id/approve",
    ...base,
    authorize("tor.approve"),
    validate(approveTorSchema),
    approveTor
);

router.post(
    "/:id/return",
    ...base,
    authorize("tor.approve"),
    validate(returnTorSchema),
    returnTor
);


router.post(
    "/:id/create-activity",
    ...base,
    authorize("tor.create_activity"),
    createActivityFromTor
);

router.post(
    "/:id/link-activity",
    ...base,
    authorize("tor.update"),
    validate(linkActivitySchema),
    linkActivity
);


module.exports = router;
