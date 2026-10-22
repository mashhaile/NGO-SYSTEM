import {
    Alert,
    Stack
} from "@mui/material";

import {
    Add,
    OpenInNew
} from "@mui/icons-material";

import {
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip
} from "../../../components/ui";

import {
    formatMoney,
    hasPermission
} from "../utils/budgetUtils";

import {
    fiscalYearLabel
} from "../../../utils/fiscalYear";


// =====================================================
// BUDGET CARD (program / project pages)
// =====================================================
// Shows the budget of a program or project from the
// Budgets module, the only source of budget numbers.
//
//   figure: { budgetId, budgetCode, status, currency,
//             startYear, endYear, totalAmount, approvedAmount,
//             spent, remaining } | null
//   level:  "program" | "project"

const BudgetFigureCard = ({ figure, level, entityId, user, navigate }) => {

    const what = level === "program" ? "program" : "project";
    const approved = figure?.status === "Approved";

    return (

        <PageCard>

            <FormSection
                title="Budget"
                subtitle={`From the Budgets module. ${level === "program" ? "Spent = approved expenses of the program's project budgets." : "Spent = approved expenses."}`}
            >

                {!figure && (
                    <Stack spacing={2} sx={{ alignItems: "flex-start" }}>
                        <Alert severity="info" sx={{ width: "100%" }}>
                            This {what} has no budget yet.
                        </Alert>
                        {hasPermission(user, "budget.create") && (
                            <AppButton
                                variant="contained"
                                startIcon={<Add />}
                                onClick={() => navigate(`/budgets/create?${what}=${entityId}`)}
                            >
                                Create Budget
                            </AppButton>
                        )}
                    </Stack>
                )}

                {figure && (
                    <>
                        <InfoRow label="Budget" value={figure.budgetCode} />
                        <InfoRow label="Status" value={<StatusChip status={figure.status} />} />
                        <InfoRow
                            label="Period"
                            value={`${fiscalYearLabel(figure.startYear)} – ${fiscalYearLabel(figure.endYear)}`}
                        />
                        <InfoRow
                            label={approved ? "Approved budget" : "Budget (not approved yet)"}
                            value={formatMoney(figure.totalAmount, figure.currency)}
                        />
                        {approved && (
                            <>
                                <InfoRow label="Spent" value={formatMoney(figure.spent, figure.currency)} />
                                <InfoRow label="Remaining" value={formatMoney(figure.remaining, figure.currency)} />
                            </>
                        )}

                        {hasPermission(user, "budget.read") && (
                            <AppButton
                                variant="outlined"
                                startIcon={<OpenInNew />}
                                sx={{ mt: 2 }}
                                onClick={() => navigate(`/budgets/${figure.budgetId}`)}
                            >
                                Open Budget
                            </AppButton>
                        )}
                    </>
                )}

            </FormSection>

        </PageCard>

    );

};


export default BudgetFigureCard;
