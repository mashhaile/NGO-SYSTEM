import {
    Box,
    Typography
} from "@mui/material";

import {
    formatMoney
} from "../utils/budgetUtils";


// Budget column of the program / project lists: the total of
// its budget in the Budgets module, with the status under it.
const BudgetFigureCell = ({ figure }) => {

    if (!figure) {
        return (
            <Typography variant="body2" sx={{ color: "text.secondary" }}>
                No budget
            </Typography>
        );
    }

    const approved = figure.status === "Approved";

    return (
        <Box sx={{ lineHeight: 1.3, py: 0.5, textAlign: "right" }}>
            <Typography variant="body2" sx={{ whiteSpace: "nowrap", color: approved ? "text.primary" : "text.secondary" }}>
                {formatMoney(figure.totalAmount, figure.currency)}
            </Typography>
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                {approved ? `Spent ${formatMoney(figure.spent, figure.currency)}` : figure.status}
            </Typography>
        </Box>
    );

};


export default BudgetFigureCell;
