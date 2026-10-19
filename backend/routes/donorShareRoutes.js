const express =
    require("express");

const rateLimit =
    require("express-rate-limit");

const authMiddleware =
    require("../middleware/authMiddleware");

const subscriptionMiddleware =
    require("../middleware/subscriptionMiddleware");

const authorize =
    require("../middleware/authorize");

const validate =
    require("../middleware/validate");

const {
    createShareLink,
    listShareLinks,
    revokeShareLink,
    getPublicView,
    downloadPublicStatement
} = require("../controllers/donorShareController");

const {
    createShareLinkSchema
} = require("../validators/donorShareValidator");



// =====================================================
// STAFF: /api/v1/donor-share-links
// =====================================================
//
// GET    /?donor=:donorId     list a donor's links
// POST   /                    create (token shown once)
// POST   /:id/revoke          revoke
//
// =====================================================

const staffRouter =
    express.Router();

const base = [
    authMiddleware,
    subscriptionMiddleware
];

staffRouter.get(
    "/",
    ...base,
    authorize("donor.read"),
    listShareLinks
);

staffRouter.post(
    "/",
    ...base,
    authorize("donor.share"),
    validate(createShareLinkSchema),
    createShareLink
);

staffRouter.post(
    "/:id/revoke",
    ...base,
    authorize("donor.share"),
    revokeShareLink
);



// =====================================================
// PUBLIC: /api/v1/public/donor-share
// =====================================================
//
// GET /:token                          donor view
// GET /:token/statement/:donationId    statement PDF
//
// No login. Stricter rate limit to stop token guessing.
//
// =====================================================

const publicRouter =
    express.Router();

const publicLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 60,
        standardHeaders: true,
        legacyHeaders: false,
        message: {
            success: false,
            message: "Too many requests. Please try again later."
        }
    });

publicRouter.use(publicLimiter);

publicRouter.get(
    "/:token",
    getPublicView
);

publicRouter.get(
    "/:token/statement/:donationId",
    downloadPublicStatement
);


module.exports = {
    staffRouter,
    publicRouter
};
