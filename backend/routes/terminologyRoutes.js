const express = require("express");

const authMiddleware = require("../middleware/authMiddleware");
const authorize = require("../middleware/authorize");
const { getErrorStatus, getErrorMessage } = require("../utils/errorStatus");
const terminology = require("../services/terminologyService");

// =====================================================
// THE ORGANIZATION'S OWN WORDS
//   GET /terminology   every signed-in user (screens use them)
//   PUT /terminology   { terms: { donation: { singular, plural } } }
// =====================================================

const router = express.Router();

const respond = (handler) => async (req, res) => {
    try {
        res.json({ success: true, data: await handler(req) });
    }
    catch (error) {
        res.status(getErrorStatus(error)).json({ success: false, message: getErrorMessage(error) });
    }
};

router.get("/", authMiddleware, respond(req => terminology.getTerms(req.user.organizationId)));
router.put("/", authMiddleware, authorize("organization.update"), respond(req => terminology.updateTerms(req.user.organizationId, req.body?.terms || {})));

module.exports = router;
