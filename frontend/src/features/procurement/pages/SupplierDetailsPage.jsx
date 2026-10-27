import {
    useEffect,
    useState
} from "react";

import {
    useNavigate,
    useParams
} from "react-router-dom";

import {
    Alert,
    Link,
    Stack,
    Typography
} from "@mui/material";

import {
    ArrowBack,
    Edit
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    InfoRow,
    AppButton,
    StatusChip,
    LoadingState
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import {
    getSupplierByIdApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    formatMoney,
    hasPermission
} from "../../budgets/utils/budgetUtils";

import {
    SUPPLIER_STATUS,
    formatDate
} from "../utils/procurementUtils";


// =====================================================
// SUPPLIER DETAILS
// =====================================================

const SupplierDetailsPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const { user } = useAuth();

    const [supplier, setSupplier] = useState(null);
    const [error, setError] = useState("");


    useEffect(() => {
        getSupplierByIdApi(id)
            .then(setSupplier)
            .catch(err => setError(getApiErrorMessage(err, "Failed to load the supplier.")));
    }, [id]);


    const header = (
        <PageHeader
            title="Supplier Details"
            subtitle={supplier ? `${supplier.supplierCode} · ${supplier.name}` : ""}
            action={() => navigate("/suppliers")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (!supplier) {
        return (
            <PageContainer>
                {header}
                {error ? <Alert severity="error">{error}</Alert> : <PageCard><LoadingState message="Loading supplier..." /></PageCard>}
            </PageContainer>
        );
    }

    return (

        <PageContainer>

            {header}

            {supplier.status !== SUPPLIER_STATUS.ACTIVE && (
                <Alert severity={supplier.status === SUPPLIER_STATUS.BLACKLISTED ? "error" : "info"} sx={{ mb: 3 }}>
                    <strong>{supplier.status}</strong>{supplier.statusReason ? `: ${supplier.statusReason}` : ""}. Not offered for new purchase requests.
                </Alert>
            )}

            {hasPermission(user, "supplier.update") && (
                <PageCard>
                    <Stack direction="row" spacing={1.5}>
                        <AppButton variant="outlined" startIcon={<Edit />} onClick={() => navigate(`/suppliers/${id}/edit`)}>Edit</AppButton>
                    </Stack>
                </PageCard>
            )}

            <PageCard>
                <FormSection title="Supplier">
                    <InfoRow label="Supplier Code" value={supplier.supplierCode} />
                    <InfoRow label="Name" value={supplier.name} />
                    <InfoRow label="Status" value={<StatusChip status={supplier.status} />} />
                    <InfoRow label="Category" value={(supplier.categories || []).join(", ") || "-"} />
                    <InfoRow label="What they supply" value={supplier.supplies || "-"} />
                    <InfoRow label="TIN" value={supplier.tin || "-"} />
                    <InfoRow label="VAT registered" value={supplier.vatRegistered ? "Yes" : "No"} />
                    <InfoRow label="Trade license no." value={supplier.licenseNumber || "-"} />
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Contact and Bank">
                    <InfoRow label="Contact person" value={supplier.contactPerson || "-"} />
                    <InfoRow label="Phone" value={supplier.phone || "-"} />
                    <InfoRow label="Email" value={supplier.email || "-"} />
                    <InfoRow label="Address" value={supplier.address || "-"} />
                    <InfoRow label="Bank" value={supplier.bankName || "-"} />
                    <InfoRow label="Account" value={[supplier.bankAccountName, supplier.bankAccountNumber].filter(Boolean).join(" · ") || "-"} />
                    {supplier.notes && <InfoRow label="Notes" value={supplier.notes} />}
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Purchase Requests" subtitle="Requests that suggested this supplier (latest 20).">
                    {supplier.requests?.length
                        ? supplier.requests.map(request => (
                            <InfoRow
                                key={request._id}
                                label={formatDate(request.requestDate)}
                                value={
                                    <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
                                        <Link component="button" underline="hover" onClick={() => navigate(`/purchase-requests/${request._id}`)}>
                                            {request.requestCode} · {request.title}
                                        </Link>
                                        <Typography variant="body2" color="text.secondary">{formatMoney(request.estimatedTotal, request.currency)}</Typography>
                                        <StatusChip status={request.status} />
                                    </Stack>
                                }
                            />
                        ))
                        : <Typography variant="body2" color="text.secondary">None yet.</Typography>}
                </FormSection>
            </PageCard>

        </PageContainer>

    );

};


export default SupplierDetailsPage;
