import {
    useEffect,
    useState
} from "react";

import {
    Alert,
    Box,
    Chip,
    Link,
    Stack,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography
} from "@mui/material";

import {
    Add,
    CheckCircle,
    DeleteOutlined,
    Edit,
    Gavel,
    PlayArrow,
    ReceiptLong,
    Save,
    Send,
    ThumbDown,
    ThumbUp,
    Undo
} from "@mui/icons-material";

import {
    AppButton,
    AppIconButton,
    AppSelect,
    AppTextField,
    FormGrid,
    FormSection,
    InfoRow,
    PageCard,
    StatusChip
} from "../../../components/ui";

import ExpenseActionDialog
    from "../../expenses/components/ExpenseActionDialog";

import QuoteDialog from "./QuoteDialog";
import IssueOrderDialog from "./IssueOrderDialog";

import {
    startSourcingApi,
    addQuoteApi,
    updateQuoteApi,
    removeQuoteApi,
    updateBidApi,
    submitBidApi,
    approveBidApi,
    returnBidApi,
    decideBidApi,
    issuePurchaseOrderApi,
    getProcurementSettingsApi,
    getCommitteesApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    PURCHASE_REQUEST_STATUS,
    SOURCING_STATUS,
    METHOD_KEYS,
    formatDate,
    idOf,
    userIdOf
} from "../utils/procurementUtils";


const nowrap = { whiteSpace: "nowrap" };


// the method the amount needs (same rule as the server)
const methodFor = (settings, value) => {
    const { direct, rfq, tender } = settings.methods;
    return value <= direct.upTo + 0.005 ? direct : value <= rfq.upTo + 0.005 ? rfq : tender;
};

const etbValueOf = (request) =>
    request.currency === "ETB" ? request.estimatedTotal
        : request.budgetCurrency === "ETB" ? request.budgetAmount
            : null;


// =====================================================
// QUOTATIONS AND BID ANALYSIS (purchase request page)
// =====================================================
//
// Approved request -> start (method from the amount) ->
// quotations -> choose the winner -> submit -> approved by
// an approver or the committee -> issue the purchase order.
//
// =====================================================

const SourcingCard = ({ request, user, onChange, navigate }) => {

    const sourcing = request.sourcing;
    const me = userIdOf(user);

    const [settings, setSettings] = useState(null);
    const [committees, setCommittees] = useState([]);
    const [startMethod, setStartMethod] = useState("");
    const [etbRate, setEtbRate] = useState("");

    const [choice, setChoice] = useState(null);

    const [busy, setBusy] = useState("");
    const [error, setError] = useState("");

    // "quote" | "approve" | "return" | "approveMine" | "object" | "order" | null
    const [dialog, setDialog] = useState(null);
    const [dialogKey, setDialogKey] = useState(0);
    const [editing, setEditing] = useState(null);
    const [dialogError, setDialogError] = useState("");


    const can = {
        start: hasPermission(user, "quotation.create"),
        quote: hasPermission(user, "quotation.create"),
        edit: hasPermission(user, "quotation.update"),
        approve: hasPermission(user, "quotation.approve"),
        order: hasPermission(user, "purchase_order.create")
    };

    const requestApproved = request.status === PURCHASE_REQUEST_STATUS.APPROVED;
    const editable = requestApproved && sourcing && [SOURCING_STATUS.DRAFT, SOURCING_STATUS.RETURNED].includes(sourcing.status);


    useEffect(() => {
        if (!requestApproved) return;
        getProcurementSettingsApi().then(setSettings).catch(() => setSettings(null));
    }, [requestApproved]);

    useEffect(() => {
        if (!editable || !sourcing?.needsCommittee) return;
        getCommitteesApi({ status: "Active" }).then(setCommittees).catch(() => setCommittees([]));
    }, [editable, sourcing?.needsCommittee]);


    const run = async (name, action, { closeDialog = false } = {}) => {
        setBusy(name);
        setError("");
        setDialogError("");
        try {
            const updated = await action();
            if (updated) onChange(updated);
            if (closeDialog) setDialog(null);
            setChoice(null);
        }
        catch (err) {
            const message = getApiErrorMessage(err, "The action failed.");
            if (closeDialog) setDialogError(message);
            else setError(message);
        }
        finally {
            setBusy("");
        }
    };

    const openDialog = (name, quote = null) => {
        setDialogError("");
        setEditing(quote);
        setDialogKey(key => key + 1);
        setDialog(name);
    };


    // nothing to show before approval, or for a rejected / cancelled request without quotations
    if (!sourcing && !requestApproved) return null;


    // ---------------- not started ----------------

    if (!sourcing) {

        const value = etbValueOf(request) ?? (Number(etbRate) > 0 ? request.estimatedTotal * Number(etbRate) : null);
        const byAmount = settings && value !== null ? methodFor(settings, value) : null;
        const chosen = settings && startMethod && byAmount && METHOD_KEYS.indexOf(startMethod) > METHOD_KEYS.indexOf(byAmount.key) ? settings.methods[startMethod] : byAmount;

        return (
            <PageCard>
                <FormSection title="Quotations" subtitle="Next: collect quotations from suppliers, choose one and have the choice approved; then the purchase order is issued.">

                    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

                    {etbValueOf(request) === null && (
                        <Box sx={{ mb: 2, maxWidth: 320 }}>
                            <AppTextField
                                label={`Rate: 1 ${request.currency} = ? ETB`}
                                type="number"
                                value={etbRate}
                                onChange={(e) => setEtbRate(e.target.value)}
                                helperText="The limits are in ETB"
                            />
                        </Box>
                    )}

                    {chosen && (
                        <Alert severity="info" sx={{ mb: 2 }}>
                            {formatMoney(value, "ETB")} → <strong>{chosen.name}</strong>: at least {chosen.minQuotes} quotation{chosen.minQuotes === 1 ? "" : "s"}
                            {chosen.committee ? ", approved by a committee" : ", approved by an approver"}.
                        </Alert>
                    )}

                    {can.start && (
                        <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ alignItems: { sm: "center" } }}>
                            {byAmount && byAmount.key !== "tender" && (
                                <Box sx={{ minWidth: 260 }}>
                                    <AppSelect
                                        label="Method"
                                        value={startMethod || byAmount.key}
                                        onChange={(e) => setStartMethod(e.target.value)}
                                        options={METHOD_KEYS.slice(METHOD_KEYS.indexOf(byAmount.key)).map(key => ({ value: key, label: settings.methods[key].name }))}
                                        helperText="A stricter method may be chosen"
                                    />
                                </Box>
                            )}
                            <AppButton
                                variant="contained"
                                startIcon={<PlayArrow />}
                                loading={busy === "start"}
                                disabled={value === null}
                                onClick={() => run("start", () => startSourcingApi(request._id, { method: startMethod || undefined, etbRate: etbRate ? Number(etbRate) : undefined }))}
                            >
                                Start Quotations
                            </AppButton>
                        </Stack>
                    )}

                </FormSection>
            </PageCard>
        );

    }


    // ---------------- quotations ----------------

    const quotes = sourcing.quotes || [];
    const lowest = quotes.length ? Math.min(...quotes.map(quote => quote.total)) : null;
    const lowestId = quotes.find(quote => quote.total === lowest)?._id;

    const saved = {
        selectedQuote: idOf(sourcing.selectedQuote),
        selectionReason: sourcing.selectionReason || "",
        fewerQuotesReason: sourcing.fewerQuotesReason || "",
        committee: idOf(sourcing.committee)
    };
    const form = choice || saved;
    const changed = Boolean(choice) && JSON.stringify(choice) !== JSON.stringify(saved);
    const change = (patch) => setChoice({ ...form, ...patch });

    const selected = quotes.find(quote => idOf(quote._id) === form.selectedQuote) || null;
    const winner = quotes.find(quote => idOf(quote._id) === idOf(sourcing.selectedQuote)) || null;
    const notLowest = selected && selected.total > lowest + 0.005;
    const fewer = quotes.length < sourcing.minQuotes;

    const committeeMode = sourcing.needsCommittee;
    const seat = (sourcing.panel || []).find(member => idOf(member.user) === me);
    const approvals = (sourcing.panel || []).filter(member => member.decision === "Approve").length;

    const priceOf = (quote, item) => quote.items?.find(entry => idOf(entry.item) === idOf(item._id));

    const saveChoice = () => run("save", () => updateBidApi(request._id, form));
    const submit = () => run("submit", async () => {
        if (changed) await updateBidApi(request._id, form);
        return submitBidApi(request._id);
    });


    return (

        <PageCard>

            <FormSection
                title="Quotations and Bid Analysis"
                subtitle={`${sourcing.methodName}: at least ${sourcing.minQuotes} quotation${sourcing.minQuotes === 1 ? "" : "s"}, ${committeeMode ? "approved by a committee" : "approved by an approver"}. Prices in ${request.currency}.`}
            >

                <Stack direction="row" spacing={1} sx={{ mb: 2, alignItems: "center", flexWrap: "wrap" }}>
                    <Typography variant="body2" color="text.secondary">Bid analysis:</Typography>
                    <StatusChip status={sourcing.status} />
                    {committeeMode && sourcing.committeeName && <Chip size="small" icon={<Gavel />} label={sourcing.committeeName} />}
                </Stack>

                {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

                {sourcing.reviewComment && [SOURCING_STATUS.RETURNED, SOURCING_STATUS.DRAFT].includes(sourcing.status) && (
                    <Alert severity="warning" sx={{ mb: 2 }}>{sourcing.reviewComment}</Alert>
                )}

                {sourcing.status === SOURCING_STATUS.APPROVED && (
                    <Alert severity="success" sx={{ mb: 2 }}>
                        Approved{sourcing.approvedAt ? ` on ${formatDate(sourcing.approvedAt)}` : ""}: <strong>{winner?.supplier?.name}</strong>, {formatMoney(winner?.total || 0, request.currency)}.
                        {request.status === PURCHASE_REQUEST_STATUS.ORDERED && request.purchaseOrder && (
                            <> Purchase order{" "}
                                <Link component="button" underline="hover" onClick={() => navigate(`/purchase-orders/${idOf(request.purchaseOrder)}`)}>
                                    {request.purchaseOrder.poCode}
                                </Link> issued.
                            </>
                        )}
                    </Alert>
                )}


                {/* comparison: items x suppliers */}

                {quotes.length === 0
                    ? (
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                            No quotations yet.
                        </Typography>
                    )
                    : (
                        <TableContainer sx={{ mb: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                            <Table size="small">
                                <TableHead>
                                    <TableRow>
                                        <TableCell sx={{ minWidth: 180 }}>Item</TableCell>
                                        <TableCell align="right">Qty</TableCell>
                                        <TableCell align="right" sx={nowrap}>Estimate</TableCell>
                                        {quotes.map(quote => (
                                            <TableCell key={quote._id} align="right" sx={{ minWidth: 150, bgcolor: idOf(quote._id) === form.selectedQuote ? "success.light" : undefined }}>
                                                <Typography variant="body2" sx={{ fontWeight: 700 }}>{quote.supplier?.name}</Typography>
                                                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                                    {[quote.reference, quote.quoteDate && formatDate(quote.quoteDate)].filter(Boolean).join(" · ") || "-"}
                                                </Typography>
                                                {editable && can.edit && (
                                                    <Box>
                                                        <AppIconButton icon={<Edit fontSize="small" />} tooltip="Edit quotation" onClick={() => openDialog("quote", quote)} />
                                                        <AppIconButton icon={<DeleteOutlined fontSize="small" />} tooltip="Remove quotation" color="error" disabled={Boolean(busy)} onClick={() => run("remove", () => removeQuoteApi(request._id, quote._id))} />
                                                    </Box>
                                                )}
                                            </TableCell>
                                        ))}
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {(request.items || []).map(item => {
                                        const prices = quotes.map(quote => priceOf(quote, item)?.total ?? Infinity);
                                        const best = Math.min(...prices);
                                        return (
                                            <TableRow key={item._id}>
                                                <TableCell>{item.description}</TableCell>
                                                <TableCell align="right">{Number(item.quantity).toLocaleString("en-US")} {item.unit}</TableCell>
                                                <TableCell align="right" sx={{ ...nowrap, color: "text.secondary" }}>{formatMoney(item.total, request.currency)}</TableCell>
                                                {quotes.map(quote => {
                                                    const price = priceOf(quote, item);
                                                    return (
                                                        <TableCell key={quote._id} align="right" sx={{ ...nowrap, fontWeight: price?.total === best ? 700 : 400, color: price?.total === best && quotes.length > 1 ? "success.dark" : undefined }}>
                                                            {price ? formatMoney(price.total, request.currency) : "-"}
                                                            {price && (
                                                                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                                                    {formatMoney(price.unitPrice, request.currency)} each
                                                                </Typography>
                                                            )}
                                                        </TableCell>
                                                    );
                                                })}
                                            </TableRow>
                                        );
                                    })}
                                    <TableRow>
                                        <TableCell colSpan={2} sx={{ fontWeight: 700 }}>Total</TableCell>
                                        <TableCell align="right" sx={{ ...nowrap, color: "text.secondary" }}>{formatMoney(request.estimatedTotal, request.currency)}</TableCell>
                                        {quotes.map(quote => (
                                            <TableCell key={quote._id} align="right" sx={{ ...nowrap, fontWeight: 800, color: idOf(quote._id) === idOf(lowestId) ? "success.dark" : undefined }}>
                                                {formatMoney(quote.total, request.currency)}
                                                {idOf(quote._id) === idOf(lowestId) && quotes.length > 1 && <Typography variant="caption" sx={{ display: "block" }}>lowest</Typography>}
                                            </TableCell>
                                        ))}
                                    </TableRow>
                                    <TableRow>
                                        <TableCell colSpan={3} sx={{ color: "text.secondary" }}>Delivery · valid until</TableCell>
                                        {quotes.map(quote => (
                                            <TableCell key={quote._id} align="right" sx={{ color: "text.secondary" }}>
                                                {quote.deliveryDays !== null && quote.deliveryDays !== undefined ? `${quote.deliveryDays} days` : "-"}
                                                {quote.validUntil ? ` · ${formatDate(quote.validUntil)}` : ""}
                                                {quote.notes && <Typography variant="caption" sx={{ display: "block" }}>{quote.notes}</Typography>}
                                            </TableCell>
                                        ))}
                                    </TableRow>
                                </TableBody>
                            </Table>
                        </TableContainer>
                    )}

                {editable && can.quote && (
                    <AppButton variant="outlined" startIcon={<Add />} onClick={() => openDialog("quote")} sx={{ mb: 2 }}>
                        Add Quotation
                    </AppButton>
                )}

                {editable && fewer && (
                    <Alert severity="info" sx={{ mb: 2 }}>
                        {quotes.length} of at least {sourcing.minQuotes} quotations. You can go ahead with fewer only with a reason (e.g. only one supplier sells it).
                    </Alert>
                )}


                {/* the choice */}

                {editable && can.edit && quotes.length > 0 && (
                    <Box sx={{ p: 2, borderRadius: 2, bgcolor: "action.hover", mb: 2 }}>
                        <FormGrid columns={2}>
                            <AppSelect
                                label="Winning quotation"
                                required
                                value={form.selectedQuote}
                                onChange={(e) => change({ selectedQuote: e.target.value })}
                                options={quotes.map(quote => ({ value: idOf(quote._id), label: `${quote.supplier?.name} · ${formatMoney(quote.total, request.currency)}${idOf(quote._id) === idOf(lowestId) ? " (lowest)" : ""}` }))}
                            />
                            {committeeMode
                                ? (
                                    <AppSelect
                                        label="Committee"
                                        required
                                        value={form.committee}
                                        onChange={(e) => change({ committee: e.target.value })}
                                        options={committees.map(item => ({ value: item._id, label: `${item.name} (${item.approvalsNeeded} of ${item.members.length} must approve)` }))}
                                        helperText={committees.length ? "" : "No active committee yet: add one in Procurement Setup."}
                                    />
                                )
                                : <Box />}
                        </FormGrid>
                        {notLowest && (
                            <Box sx={{ mt: 2 }}>
                                <AppTextField
                                    label="Why not the lowest? (required)"
                                    value={form.selectionReason}
                                    onChange={(e) => change({ selectionReason: e.target.value })}
                                    placeholder="e.g. faster delivery, better warranty, the lowest did not meet the specification"
                                />
                            </Box>
                        )}
                        {fewer && (
                            <Box sx={{ mt: 2 }}>
                                <AppTextField
                                    label={`Why fewer than ${sourcing.minQuotes} quotations? (required)`}
                                    value={form.fewerQuotesReason}
                                    onChange={(e) => change({ fewerQuotesReason: e.target.value })}
                                />
                            </Box>
                        )}
                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ mt: 2, justifyContent: "flex-end" }}>
                            <AppButton variant="outlined" startIcon={<Save />} loading={busy === "save"} disabled={!changed || Boolean(busy)} onClick={saveChoice}>
                                Save
                            </AppButton>
                            <AppButton variant="contained" startIcon={<Send />} loading={busy === "submit"} disabled={!form.selectedQuote || Boolean(busy)} onClick={submit}>
                                Submit for Approval
                            </AppButton>
                        </Stack>
                    </Box>
                )}


                {/* decided after submission */}

                {sourcing.status !== SOURCING_STATUS.DRAFT && (winner || sourcing.selectionReason || sourcing.fewerQuotesReason) && !editable && (
                    <Box sx={{ mb: 2 }}>
                        <InfoRow label="Chosen" value={winner ? `${winner.supplier?.name} · ${formatMoney(winner.total, request.currency)}${idOf(winner._id) === idOf(lowestId) ? " (lowest)" : ""}` : "-"} />
                        {sourcing.selectionReason && <InfoRow label="Why not the lowest" value={sourcing.selectionReason} />}
                        {sourcing.fewerQuotesReason && <InfoRow label="Fewer quotations" value={sourcing.fewerQuotesReason} />}
                        {sourcing.submittedBy?.name && <InfoRow label="Submitted by" value={`${sourcing.submittedBy.name}, ${formatDate(sourcing.submittedAt)}`} />}
                        {sourcing.approvedBy?.name && !committeeMode && <InfoRow label="Approved by" value={`${sourcing.approvedBy.name}, ${formatDate(sourcing.approvedAt)}`} />}
                    </Box>
                )}

                {committeeMode && (sourcing.panel || []).length > 0 && (
                    <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>
                            {sourcing.committeeName}: {approvals} of {sourcing.approvalsNeeded} approvals needed
                        </Typography>
                        {sourcing.panel.map(member => (
                            <InfoRow
                                key={idOf(member.user)}
                                label={`${member.user?.name || "Member"} (${member.role})`}
                                value={
                                    member.decision
                                        ? <span><StatusChip status={member.decision === "Approve" ? "Approved" : "Rejected"} />{member.comment ? ` "${member.comment}"` : ""}{member.at ? ` · ${formatDate(member.at)}` : ""}</span>
                                        : sourcing.status === SOURCING_STATUS.SUBMITTED ? "Waiting" : "-"
                                }
                            />
                        ))}
                    </Box>
                )}


                {/* actions after submission */}

                {sourcing.status === SOURCING_STATUS.SUBMITTED && requestApproved && (
                    <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5}>
                        {!committeeMode && can.approve && (
                            <AppButton variant="contained" color="success" startIcon={<CheckCircle />} onClick={() => openDialog("approve")}>Approve Bid Analysis</AppButton>
                        )}
                        {committeeMode && seat && !seat.decision && (
                            <>
                                <AppButton variant="contained" color="success" startIcon={<ThumbUp />} onClick={() => openDialog("approveMine")}>Approve (as member)</AppButton>
                                <AppButton variant="outlined" color="error" startIcon={<ThumbDown />} onClick={() => openDialog("object")}>Object</AppButton>
                            </>
                        )}
                        {can.approve && (
                            <AppButton variant="outlined" color="warning" startIcon={<Undo />} onClick={() => openDialog("return")}>Return for Changes</AppButton>
                        )}
                    </Stack>
                )}

                {sourcing.status === SOURCING_STATUS.APPROVED && requestApproved && can.order && (
                    <AppButton variant="contained" startIcon={<ReceiptLong />} onClick={() => openDialog("order")}>
                        Issue Purchase Order
                    </AppButton>
                )}

            </FormSection>


            {dialog === "quote" && (
                <QuoteDialog
                    key={`quote-${dialogKey}`}
                    open
                    request={request}
                    quote={editing}
                    loading={busy === "quote"}
                    error={dialogError}
                    onClose={() => !busy && setDialog(null)}
                    onSave={(body) => run("quote", () => (editing ? updateQuoteApi(request._id, editing._id, body) : addQuoteApi(request._id, body)), { closeDialog: true })}
                />
            )}

            <ExpenseActionDialog
                key={`approve-${dialogKey}`}
                open={dialog === "approve"}
                title="Approve Bid Analysis"
                message={`${winner?.supplier?.name || "The chosen supplier"} at ${formatMoney(winner?.total || 0, request.currency)}. Then the purchase order can be issued.`}
                confirmLabel="Approve"
                confirmColor="success"
                loading={busy === "approve"}
                error={dialogError}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("approve", () => approveBidApi(request._id, comment), { closeDialog: true })}
            />

            <ExpenseActionDialog
                key={`mine-${dialogKey}`}
                open={dialog === "approveMine"}
                title={`Approve as a member of ${sourcing.committeeName}`}
                message={`${winner?.supplier?.name || "The chosen supplier"} at ${formatMoney(winner?.total || 0, request.currency)}. ${sourcing.approvalsNeeded} approval${sourcing.approvalsNeeded === 1 ? "" : "s"} needed; ${approvals} so far.`}
                confirmLabel="Approve"
                confirmColor="success"
                loading={busy === "decide"}
                error={dialogError}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("decide", () => decideBidApi(request._id, "Approve", comment), { closeDialog: true })}
            />

            <ExpenseActionDialog
                key={`object-${dialogKey}`}
                open={dialog === "object"}
                title="Object to the Bid Analysis"
                message="Your reason is shown to the officer. If too many members object for it to be approved, it goes back to the officer."
                commentLabel="Why you object"
                requireComment
                confirmLabel="Object"
                confirmColor="error"
                loading={busy === "decide"}
                error={dialogError}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("decide", () => decideBidApi(request._id, "Object", comment), { closeDialog: true })}
            />

            <ExpenseActionDialog
                key={`return-${dialogKey}`}
                open={dialog === "return"}
                title="Return the Bid Analysis"
                message="The officer will see your comment, can change the quotations or the choice, and submit again."
                commentLabel="What needs to change"
                requireComment
                confirmLabel="Return"
                confirmColor="warning"
                loading={busy === "return"}
                error={dialogError}
                onClose={() => !busy && setDialog(null)}
                onConfirm={({ comment }) => run("return", () => returnBidApi(request._id, comment), { closeDialog: true })}
            />

            {dialog === "order" && (
                <IssueOrderDialog
                    key={`order-${dialogKey}`}
                    open
                    request={request}
                    winner={winner}
                    loading={busy === "order"}
                    error={dialogError}
                    onClose={() => !busy && setDialog(null)}
                    onIssue={(body) => run("order", async () => {
                        const order = await issuePurchaseOrderApi(request._id, body);
                        navigate(`/purchase-orders/${order._id}`);
                        return null;
                    }, { closeDialog: true })}
                />
            )}

        </PageCard>

    );

};


export default SourcingCard;
