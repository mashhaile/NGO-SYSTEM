const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");

const PERMISSIONS = require("../constants/permissions");

const controller = require("../controllers/budgetController");

const {
    createBudgetSchema,
    updateBudgetSchema,
    approveBudgetSchema,
    returnBudgetSchema
} = require("../validators/budgetValidator");


// =====================================================
// BUDGETS (master budget)
// =====================================================
//
// GET    /budgets              list (level, program, project, status, fiscalYear, search, page, limit)
// POST   /budgets              create (Draft)
// GET    /budgets/:id          details + summary (per year, allocation, lines)
// PUT    /budgets/:id          edit (Draft / Returned only)
// DELETE /budgets/:id          delete (Draft / Returned only)
// POST   /budgets/:id/submit   Draft / Returned -> Submitted
// POST   /budgets/:id/approve  Submitted -> Approved   (budget.approve)
// POST   /budgets/:id/return   Submitted -> Returned   (budget.approve, comment required)
//
// =====================================================

const base = [
    authMiddleware,
    subscriptionMiddleware
];


router.get("/", ...base, authorize(PERMISSIONS.BUDGET_READ), controller.getBudgets);

router.post("/", ...base, authorize(PERMISSIONS.BUDGET_CREATE), validate(createBudgetSchema), controller.createBudget);

router.get("/:id", ...base, authorize(PERMISSIONS.BUDGET_READ), controller.getBudgetById);

router.put("/:id", ...base, authorize(PERMISSIONS.BUDGET_UPDATE), validate(updateBudgetSchema), controller.updateBudget);

router.delete("/:id", ...base, authorize(PERMISSIONS.BUDGET_DELETE), controller.deleteBudget);

router.post("/:id/submit", ...base, authorize(PERMISSIONS.BUDGET_UPDATE), controller.submitBudget);

router.post("/:id/approve", ...base, authorize(PERMISSIONS.BUDGET_APPROVE), validate(approveBudgetSchema), controller.approveBudget);

router.post("/:id/return", ...base, authorize(PERMISSIONS.BUDGET_APPROVE), validate(returnBudgetSchema), controller.returnBudget);


module.exports = router;
