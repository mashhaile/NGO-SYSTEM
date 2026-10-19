import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    Alert,
    Box,
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
    CheckCircle,
    Delete,
    Edit,
    PictureAsPdf,
    Replay,
    Send
} from "@mui/icons-material";


import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip,
    LoadingState,
    ConfirmDialog,
    ConfirmDeleteDialog
} from "../../../components/ui";


import useAuth
    from "../../auth/hooks/useAuth";


import useZoneLabel
    from "../../locations/hooks/useZoneLabel";


import {
    getTorByIdApi,
    submitTorApi,
    approveTorApi,
    returnTorApi,
    deleteTorApi,
    downloadTorPdfApi,
    getApiErrorMessage
} from "../api/torApi";


import {
    getTorActions
} from "../utils/torPermissions";


import {
    formatAmount
} from "../utils/torBudget";


import TorReviewDialog
    from "../components/TorReviewDialog";



// =====================================================
// FORMATTERS
// =====================================================

const formatDate = (value) =>
    value
        ? new Date(value).toLocaleDateString()
        : "-";


const formatDateTime = (value) =>
    value
        ? new Date(value).toLocaleString()
        : "-";


const codeName = (item, codeKey) =>
    item && typeof item === "object"
        ? [item[codeKey], item.name]
            .filter(Boolean)
            .join(" - ")
        : "-";


const personName = (user) =>
    user?.name ||
    user?.email ||
    "-";


// Multi-line text shown as written.

const Paragraph = ({ value }) =>
    value
        ? (
            <Box
                component="span"
                sx={{
                    whiteSpace: "pre-line"
                }}
            >
                {value}
            </Box>
        )
        : "-";



// =====================================================
// TOR DETAILS PAGE
// =====================================================

const TorDetailsPage = () => {

    const {
        id
    } = useParams();

    const navigate =
        useNavigate();

    const {
        user
    } = useAuth();

    const [tor, setTor] =
        useState(null);

    const [loading, setLoading] =
        useState(true);

    const [loadError, setLoadError] =
        useState("");

    // dialog: null | "submit" | "approve" | "return" | "delete"

    const [dialog, setDialog] =
        useState(null);

    const [dialogKey, setDialogKey] =
        useState(0);

    const [busy, setBusy] =
        useState(false);

    const [actionError, setActionError] =
        useState("");

    const [notice, setNotice] =
        useState("");

    const zoneLabel =
        useZoneLabel(
            tor?.regionCode
        );


    // =================================================
    // LOAD
    // =================================================

    useEffect(() => {

        let cancelled = false;

        getTorByIdApi(id)

            .then(data => {
                if (!cancelled) {
                    setTor(data);
                }
            })

            .catch(error => {
                if (!cancelled) {
                    setLoadError(
                        getApiErrorMessage(
                            error,
                            "Failed to load the TOR."
                        )
                    );
                }
            })

            .finally(() => {
                if (!cancelled) {
                    setLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id]);


    // =================================================
    // ACTIONS
    // =================================================

    const openDialog = (name) => {

        setActionError("");

        setDialogKey(key => key + 1);

        setDialog(name);

    };


    const closeDialog = () => {

        if (!busy) {
            setDialog(null);
        }

    };


    const runAction = useCallback(
        async (action, successMessage) => {

            setBusy(true);

            setActionError("");

            try {

                const updated =
                    await action();

                if (updated) {
                    setTor(updated);
                }

                setDialog(null);

                setNotice(successMessage);

            }
            catch (error) {

                setActionError(
                    getApiErrorMessage(
                        error,
                        "The action could not be completed."
                    )
                );

            }
            finally {

                setBusy(false);

            }

        },
        []
    );


    const handleDelete = async () => {

        setBusy(true);

        try {

            await deleteTorApi(id);

            navigate("/tors");

        }
        catch (error) {

            setDialog(null);

            setActionError(
                getApiErrorMessage(
                    error,
                    "Failed to delete the TOR."
                )
            );

        }
        finally {

            setBusy(false);

        }

    };


    const handlePdf = async () => {

        try {

            await downloadTorPdfApi(
                id,
                `${tor.torNumber}.pdf`
            );

        }
        catch (error) {

            setActionError(
                getApiErrorMessage(
                    error,
                    "Failed to download the PDF."
                )
            );

        }

    };


    const backButton = (

        <AppButton
            variant="outlined"
            onClick={() =>
                navigate("/tors")
            }
            sx={{
                mt: 3,
                mb: 5
            }}
        >
            Back to Terms of Reference
        </AppButton>

    );


    // =================================================
    // LOADING / NOT FOUND
    // =================================================

    if (loading) {

        return (

            <PageContainer>

                <PageHeader
                    title="Terms of Reference"
                    subtitle="Loading TOR..."
                />

                <LoadingState
                    message="Loading TOR..."
                />

            </PageContainer>

        );

    }


    if (loadError || !tor) {

        return (

            <PageContainer>

                <PageHeader
                    title="Terms of Reference"
                    subtitle="The TOR could not be found."
                />

                <PageCard>

                    <FormSection
                        title="Record Not Found"
                    >

                        <InfoRow
                            label="TOR"
                            value={loadError || "No TOR information available."}
                        />

                    </FormSection>

                </PageCard>

                {backButton}

            </PageContainer>

        );

    }


    const actions =
        getTorActions(
            user,
            tor
        );

    const location =
        [
            tor.venue,
            tor.woreda,
            tor.zone,
            tor.region
        ]
            .filter(Boolean)
            .join(", ");



    // =================================================
    // PAGE
    // =================================================

    return (

        <PageContainer>

            <PageHeader
                title={tor.title}
                subtitle={`Terms of Reference · ${tor.torNumber}`}
            />


            {notice && (

                <Alert
                    severity="success"
                    sx={{ mb: 3 }}
                    onClose={() => setNotice("")}
                >
                    {notice}
                </Alert>

            )}


            {actionError && !dialog && (

                <Alert
                    severity="error"
                    sx={{ mb: 3 }}
                    onClose={() => setActionError("")}
                >
                    {actionError}
                </Alert>

            )}


            {tor.status === "Returned" && tor.reviewComment && (

                <Alert
                    severity="warning"
                    sx={{ mb: 3 }}
                >
                    <strong>Returned for revision:</strong> {tor.reviewComment}
                </Alert>

            )}


            {/* ACTIONS */}

            <PageCard
                sx={{
                    mb: 3
                }}
            >

                <FormSection
                    sx={{
                        mb: 0
                    }}
                >

                    <Stack
                        direction={{
                            xs: "column",
                            md: "row"
                        }}
                        spacing={1.5}
                        alignItems={{
                            xs: "stretch",
                            md: "center"
                        }}
                        justifyContent="space-between"
                    >

                        <Stack
                            direction={{
                                xs: "column",
                                sm: "row"
                            }}
                            spacing={1.5}
                            useFlexGap
                            flexWrap="wrap"
                        >

                            {actions.canEdit && (
                                <AppButton
                                    variant="contained"
                                    startIcon={<Edit />}
                                    onClick={() =>
                                        navigate(`/tors/${id}/edit`)
                                    }
                                >
                                    Edit TOR
                                </AppButton>
                            )}

                            {actions.canSubmit && (
                                <AppButton
                                    variant="contained"
                                    color="primary"
                                    startIcon={<Send />}
                                    onClick={() => openDialog("submit")}
                                >
                                    Submit for Approval
                                </AppButton>
                            )}

                            {actions.canReview && (
                                <AppButton
                                    variant="contained"
                                    color="success"
                                    startIcon={<CheckCircle />}
                                    onClick={() => openDialog("approve")}
                                >
                                    Approve
                                </AppButton>
                            )}

                            {actions.canReview && (
                                <AppButton
                                    variant="outlined"
                                    color="warning"
                                    startIcon={<Replay />}
                                    onClick={() => openDialog("return")}
                                >
                                    Return for Revision
                                </AppButton>
                            )}

                            <AppButton
                                variant="outlined"
                                startIcon={<PictureAsPdf />}
                                onClick={handlePdf}
                            >
                                Download PDF
                            </AppButton>

                            {actions.canDelete && (
                                <AppButton
                                    variant="outlined"
                                    color="error"
                                    startIcon={<Delete />}
                                    onClick={() => openDialog("delete")}
                                >
                                    Delete
                                </AppButton>
                            )}

                        </Stack>

                        <Stack
                            direction="row"
                            spacing={1}
                            alignItems="center"
                        >

                            <Typography
                                variant="body2"
                                color="text.secondary"
                            >
                                Status:
                            </Typography>

                            <StatusChip
                                status={tor.status}
                            />

                        </Stack>

                    </Stack>

                </FormSection>

            </PageCard>


            {/* TOR INFORMATION */}

            <PageCard>

                <FormSection
                    title="TOR Information"
                >

                    <InfoRow label="TOR No." value={tor.torNumber} />

                    <InfoRow label="Title" value={tor.title} />

                    <InfoRow
                        label="Activity"
                        value={codeName(tor.activity, "activityCode")}
                    />

                    <InfoRow
                        label="Activity Run"
                        value={codeName(tor.activityRun, "runCode")}
                    />

                    <InfoRow
                        label="Project"
                        value={codeName(tor.project, "projectCode")}
                    />

                </FormSection>

            </PageCard>


            {/* PURPOSE */}

            <PageCard>

                <FormSection
                    title="Purpose"
                >

                    <InfoRow label="Background" value={<Paragraph value={tor.background} />} />

                    <InfoRow label="Objectives" value={<Paragraph value={tor.objectives} />} />

                    <InfoRow label="Expected Outputs" value={<Paragraph value={tor.expectedOutputs} />} />

                    <InfoRow label="Methodology" value={<Paragraph value={tor.methodology} />} />

                </FormSection>

            </PageCard>


            {/* PARTICIPANTS */}

            <PageCard>

                <FormSection
                    title="Participants and Facilitators"
                >

                    <InfoRow label="Participants" value={<Paragraph value={tor.participants} />} />

                    <InfoRow
                        label="Expected Number"
                        value={tor.expectedParticipants || "-"}
                    />

                    <InfoRow label="Facilitators" value={<Paragraph value={tor.facilitators} />} />

                </FormSection>

            </PageCard>


            {/* DATE AND VENUE */}

            <PageCard>

                <FormSection
                    title="Date and Venue"
                >

                    <InfoRow label="Start Date" value={formatDate(tor.startDate)} />

                    <InfoRow label="End Date" value={formatDate(tor.endDate)} />

                    <InfoRow label="Region" value={tor.region} />

                    <InfoRow label={zoneLabel} value={tor.zone} />

                    <InfoRow label="Woreda" value={tor.woreda} />

                    <InfoRow label="Venue" value={tor.venue} />

                    <InfoRow label="Full Location" value={location || "-"} />

                </FormSection>

            </PageCard>


            {/* BUDGET */}

            <PageCard>

                <FormSection
                    title="Budget"
                    subtitle={`Total: ${formatAmount(tor.totalBudget, tor.currency)}`}
                >

                    {tor.budgetLines?.length
                        ? (

                            <TableContainer
                                sx={{
                                    border: "1px solid",
                                    borderColor: "divider",
                                    borderRadius: 2
                                }}
                            >

                                <Table size="small">

                                    <TableHead>
                                        <TableRow>
                                            <TableCell>#</TableCell>
                                            <TableCell>Description</TableCell>
                                            <TableCell>Unit</TableCell>
                                            <TableCell align="right">Quantity</TableCell>
                                            <TableCell align="right">Unit Cost</TableCell>
                                            <TableCell align="right">Total</TableCell>
                                        </TableRow>
                                    </TableHead>

                                    <TableBody>

                                        {tor.budgetLines.map((line, index) => (

                                            <TableRow key={line._id || index}>
                                                <TableCell>{index + 1}</TableCell>
                                                <TableCell>{line.description}</TableCell>
                                                <TableCell>{line.unit || "-"}</TableCell>
                                                <TableCell align="right">{line.quantity}</TableCell>
                                                <TableCell align="right">
                                                    {formatAmount(line.unitCost, tor.currency)}
                                                </TableCell>
                                                <TableCell align="right">
                                                    {formatAmount(line.total, tor.currency)}
                                                </TableCell>
                                            </TableRow>

                                        ))}

                                        <TableRow>
                                            <TableCell colSpan={5} align="right">
                                                <Typography fontWeight={700}>
                                                    Total Budget
                                                </Typography>
                                            </TableCell>
                                            <TableCell align="right">
                                                <Typography fontWeight={700}>
                                                    {formatAmount(tor.totalBudget, tor.currency)}
                                                </Typography>
                                            </TableCell>
                                        </TableRow>

                                    </TableBody>

                                </Table>

                            </TableContainer>

                        )
                        : (
                            <InfoRow
                                label="Budget"
                                value="No budget lines."
                            />
                        )}

                </FormSection>

            </PageCard>


            {/* LOGISTICS AND REPORTING */}

            <PageCard>

                <FormSection
                    title="Logistics and Reporting"
                >

                    <InfoRow label="Logistics" value={<Paragraph value={tor.logistics} />} />

                    <InfoRow
                        label="Reporting Requirements"
                        value={<Paragraph value={tor.reportingRequirements} />}
                    />

                </FormSection>

            </PageCard>


            {/* APPROVAL HISTORY */}

            <PageCard>

                <FormSection
                    title="Approval History"
                >

                    {(tor.history || [])
                        .slice()
                        .reverse()
                        .map((entry, index) => (

                            <InfoRow
                                key={`${entry.at}-${index}`}
                                label={entry.action}
                                value={
                                    <>
                                        {personName(entry.by)} · {formatDateTime(entry.at)}
                                        {entry.comment && (
                                            <Typography
                                                variant="body2"
                                                color="text.secondary"
                                                sx={{
                                                    mt: 0.5,
                                                    whiteSpace: "pre-line"
                                                }}
                                            >
                                                “{entry.comment}”
                                            </Typography>
                                        )}
                                    </>
                                }
                            />

                        ))}

                </FormSection>

            </PageCard>


            {/* RECORD */}

            <PageCard>

                <FormSection
                    title="Record Information"
                >

                    <InfoRow
                        label="Status"
                        value={<StatusChip status={tor.status} />}
                    />

                    <InfoRow label="Prepared By" value={personName(tor.createdBy)} />

                    <InfoRow label="Submitted By" value={tor.submittedBy ? personName(tor.submittedBy) : "-"} />

                    <InfoRow label="Submitted At" value={formatDateTime(tor.submittedAt)} />

                    <InfoRow label="Approved By" value={tor.approvedBy ? personName(tor.approvedBy) : "-"} />

                    <InfoRow label="Approved At" value={formatDateTime(tor.approvedAt)} />

                    <InfoRow label="Created At" value={formatDateTime(tor.createdAt)} />

                    <InfoRow label="Updated At" value={formatDateTime(tor.updatedAt)} />

                </FormSection>

            </PageCard>


            {backButton}


            {/* DIALOGS */}

            <ConfirmDialog
                open={dialog === "submit"}
                title="Submit for Approval"
                message={
                    actionError ||
                    "After submitting, the TOR is locked until it is approved or returned."
                }
                confirmLabel="Submit"
                loading={busy}
                onClose={closeDialog}
                onConfirm={() =>
                    runAction(
                        () => submitTorApi(id),
                        "TOR submitted for approval."
                    )
                }
            />

            <TorReviewDialog
                key={`review-${dialogKey}`}
                open={dialog === "approve" || dialog === "return"}
                mode={dialog === "return" ? "return" : "approve"}
                loading={busy}
                error={actionError}
                onClose={closeDialog}
                onConfirm={(comment) =>
                    dialog === "return"
                        ? runAction(
                            () => returnTorApi(id, comment),
                            "TOR returned for revision."
                        )
                        : runAction(
                            () => approveTorApi(id, comment),
                            "TOR approved."
                        )
                }
            />

            <ConfirmDeleteDialog
                open={dialog === "delete"}
                title="Delete TOR"
                message={`Delete ${tor.torNumber}? This cannot be undone.`}
                loading={busy}
                onClose={closeDialog}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default TorDetailsPage;
