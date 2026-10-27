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
    Box,
    Checkbox,
    FormControlLabel,
    Stack
} from "@mui/material";

import {
    ArrowBack,
    Save
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    FormGrid,
    AppTextField,
    AppSelect,
    AppButton,
    LoadingState
} from "../../../components/ui";

import {
    getSupplierByIdApi,
    createSupplierApi,
    updateSupplierApi
} from "../api/procurementApi";

import {
    getApiErrorMessage
} from "../../budgets/api/budgetApi";

import {
    SUPPLIER_STATUS,
    SUPPLIER_CATEGORIES
} from "../utils/procurementUtils";


const FIELDS = [
    "name", "supplies", "tin", "licenseNumber", "contactPerson", "phone", "email", "address",
    "bankName", "bankAccountName", "bankAccountNumber", "statusReason", "notes"
];

const emptyForm = {
    ...Object.fromEntries(FIELDS.map(field => [field, ""])),
    categories: [],
    vatRegistered: false,
    status: SUPPLIER_STATUS.ACTIVE
};


// =====================================================
// ADD / EDIT SUPPLIER
// =====================================================

const SupplierFormPage = () => {

    const { id } = useParams();

    const isEdit = Boolean(id);

    const navigate = useNavigate();

    const [form, setForm] = useState(emptyForm);
    const [existing, setExisting] = useState(null);
    const [loading, setLoading] = useState(isEdit);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");


    useEffect(() => {

        if (!isEdit) return undefined;

        let cancelled = false;

        getSupplierByIdApi(id)
            .then(supplier => {
                if (cancelled) return;
                setExisting(supplier);
                setForm({
                    ...Object.fromEntries(FIELDS.map(field => [field, supplier[field] || ""])),
                    categories: supplier.categories || [],
                    vatRegistered: Boolean(supplier.vatRegistered),
                    status: supplier.status || SUPPLIER_STATUS.ACTIVE
                });
                setLoading(false);
            })
            .catch(err => {
                if (!cancelled) {
                    setError(getApiErrorMessage(err, "Failed to load the supplier."));
                    setLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };

    }, [id, isEdit]);


    const change = (patch) => setForm(prev => ({ ...prev, ...patch }));

    const text = (field, label, extra = {}) => (
        <AppTextField
            label={label}
            value={form[field]}
            onChange={(e) => change({ [field]: e.target.value })}
            {...extra}
        />
    );


    const save = async () => {

        setError("");

        if (form.name.trim().length < 2) return setError("Enter the supplier's name.");
        if (form.status === SUPPLIER_STATUS.BLACKLISTED && form.statusReason.trim().length < 3) {
            return setError("Give the reason the supplier is blacklisted.");
        }

        setSaving(true);

        try {
            const body = {
                ...Object.fromEntries(FIELDS.map(field => [field, form[field].trim()])),
                categories: form.categories,
                vatRegistered: form.vatRegistered,
                status: form.status
            };
            const saved = isEdit ? await updateSupplierApi(id, body) : await createSupplierApi(body);
            navigate(`/suppliers/${saved._id}`);
        }
        catch (err) {
            setError(getApiErrorMessage(err, "Failed to save the supplier."));
        }
        finally {
            setSaving(false);
        }

    };


    const header = (
        <PageHeader
            title={isEdit ? "Edit Supplier" : "Add Supplier"}
            subtitle={isEdit ? existing?.supplierCode : "A supplier the organization buys from."}
            action={() => navigate(isEdit ? `/suppliers/${id}` : "/suppliers")}
            actionLabel="Back"
            actionIcon={<ArrowBack />}
        />
    );

    if (loading) {
        return <PageContainer>{header}<PageCard><LoadingState message="Loading..." /></PageCard></PageContainer>;
    }

    return (

        <PageContainer>

            {header}

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <PageCard>
                <FormSection title="Supplier">
                    <FormGrid columns={2}>
                        {text("name", "Name", { required: true, placeholder: "e.g. Abebe Stationery PLC" })}
                        <AppSelect
                            label="Category"
                            multiple
                            value={form.categories}
                            onChange={(e) => change({ categories: typeof e.target.value === "string" ? e.target.value.split(",") : e.target.value })}
                            options={SUPPLIER_CATEGORIES.map(value => ({ value, label: value }))}
                            helperText="One or more"
                        />
                    </FormGrid>
                    <Box sx={{ mt: 2 }}>
                        {text("supplies", "What they supply", { placeholder: "e.g. stationery, printing, office furniture" })}
                    </Box>
                    <Box sx={{ mt: 2 }}>
                        <FormGrid columns={3}>
                            {text("tin", "TIN")}
                            {text("licenseNumber", "Trade license no.")}
                            <FormControlLabel
                                control={<Checkbox checked={form.vatRegistered} onChange={(e) => change({ vatRegistered: e.target.checked })} />}
                                label="VAT registered"
                            />
                        </FormGrid>
                    </Box>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Contact">
                    <FormGrid columns={3}>
                        {text("contactPerson", "Contact person")}
                        {text("phone", "Phone")}
                        {text("email", "Email", { type: "email" })}
                    </FormGrid>
                    <Box sx={{ mt: 2 }}>
                        {text("address", "Address")}
                    </Box>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Bank (for payments)">
                    <FormGrid columns={3}>
                        {text("bankName", "Bank")}
                        {text("bankAccountName", "Account name")}
                        {text("bankAccountNumber", "Account number")}
                    </FormGrid>
                </FormSection>
            </PageCard>

            <PageCard>
                <FormSection title="Status">
                    <FormGrid columns={2}>
                        <AppSelect
                            label="Status"
                            value={form.status}
                            onChange={(e) => change({ status: e.target.value })}
                            options={Object.values(SUPPLIER_STATUS).map(value => ({ value, label: value }))}
                            helperText="Inactive and blacklisted suppliers are not offered for new requests."
                        />
                        {form.status !== SUPPLIER_STATUS.ACTIVE
                            ? text("statusReason", "Reason", { required: form.status === SUPPLIER_STATUS.BLACKLISTED })
                            : <Box />}
                    </FormGrid>
                    <Box sx={{ mt: 2 }}>
                        {text("notes", "Notes", { multiline: true, rows: 3 })}
                    </Box>
                </FormSection>

                <Stack direction={{ xs: "column", sm: "row" }} spacing={1.5} sx={{ justifyContent: "flex-end", mt: 1 }}>
                    <AppButton variant="outlined" onClick={() => navigate(isEdit ? `/suppliers/${id}` : "/suppliers")} disabled={saving}>
                        Cancel
                    </AppButton>
                    <AppButton variant="contained" startIcon={<Save />} onClick={save} loading={saving}>
                        {isEdit ? "Save Changes" : "Add Supplier"}
                    </AppButton>
                </Stack>
            </PageCard>

        </PageContainer>

    );

};


export default SupplierFormPage;
