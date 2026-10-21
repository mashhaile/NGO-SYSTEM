const express = require("express");

const router = express.Router();

const authMiddleware = require("../middleware/authMiddleware");
const subscriptionMiddleware = require("../middleware/subscriptionMiddleware");
const authorize = require("../middleware/authorize");
const validate = require("../middleware/validate");

const PERMISSIONS = require("../constants/permissions");

const controller = require("../controllers/expenseController");

const {
    createExpenseSchema,
    updateExpenseSchema,
    approveExpenseSchema,
    returnExpenseSchema,
    voidExpenseSchema
} = require("../validators/expenseValidator");


// =====================================================
// EXPENSES (charged to approved project budget lines)
// =====================================================
//
// GET    /expenses              list (budget, budgetLine, project, status, category, fiscalYear, from, to, search)
// POST   /expenses              record (Draft)
// GET    /expenses/:id          details + the line's budget / spent / remaining
// PUT    /expenses/:id          edit (Draft / Returned)
// DELETE /expenses/:id          delete (Draft / Returned)
// POST   /expenses/:id/submit   Draft / Returned -> Submitted
// POST   /expenses/:id/approve  Submitted -> Approved   (expense.approve; over budget needs allowOverBudget + comment)
// POST   /expenses/:id/return   Submitted -> Returned   (expense.approve; comment)
// POST   /expenses/:id/void     Approved -> Voided      (expense.approve; reason)
//
// =====================================================

const base = [
    authMiddleware,
    subscriptionMiddleware
];

router.get("/", ...base, authorize(PERMISSIONS.EXPENSE_READ), controller.getExpenses);

router.post("/", ...base, authorize(PERMISSIONS.EXPENSE_CREATE), validate(createExpenseSchema), controller.createExpense);

router.get("/:id", ...base, authorize(PERMISSIONS.EXPENSE_READ), controller.getExpenseById);

router.put("/:id", ...base, authorize(PERMISSIONS.EXPENSE_UPDATE), validate(updateExpenseSchema), controller.updateExpense);

router.delete("/:id", ...base, authorize(PERMISSIONS.EXPENSE_DELETE), controller.deleteExpense);

router.post("/:id/submit", ...base, authorize(PERMISSIONS.EXPENSE_UPDATE), controller.submitExpense);

router.post("/:id/approve", ...base, authorize(PERMISSIONS.EXPENSE_APPROVE), validate(approveExpenseSchema), controller.approveExpense);

router.post("/:id/return", ...base, authorize(PERMISSIONS.EXPENSE_APPROVE), validate(returnExpenseSchema), controller.returnExpense);

router.post("/:id/void", ...base, authorize(PERMISSIONS.EXPENSE_APPROVE), validate(voidExpenseSchema), controller.voidExpense);

module.exports = router;
