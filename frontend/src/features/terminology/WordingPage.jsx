import {
    useEffect,
    useMemo,
    useState
} from "react";

import {
    Alert,
    Box,
    Stack,
    Typography
} from "@mui/material";

import {
    Restore,
    Save
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    FormSection,
    AppButton,
    LoadingState,
    ErrorState
} from "../../components/ui";

import axiosClient
    from "../../services/axiosClient";

import {
    makeReplacer,
    setTerms
} from "../../utils/terms";

import {
    getApiErrorMessage
} from "../../utils/apiError";


// =====================================================
// WORDING
// =====================================================
//
// The organization's own words for the main terms: what
// it calls a donation, a beneficiary, a role ... Screens,
// reports and exports then use them. Empty = the default.
//
// =====================================================

const SAMPLE = "Add Donation | Donations received by Program | Beneficiaries reached | Organization Admin approves the Budget";

const WordingPage = () => {

    const [terms, setRows] = useState(null);
    const [draft, setDraft] = useState({});
    const [error, setError] = useState("");
    const [saved, setSaved] = useState("");
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        let alive = true;
        axiosClient.get("/terminology")
            .then(response => {
                if (!alive) return;
                const list = response.data.data;
                setRows(list);
                setDraft(Object.fromEntries(list.map(term => [term.key, { singular: term.own?.singular || "", plural: term.own?.plural || "" }])));
            })
            .catch(loadError => { if (alive) setError(getApiErrorMessage(loadError, "The wording could not be loaded.")); });
        return () => { alive = false; };
    }, []);

    // what the draft would look like
    const preview = useMemo(() => {
        if (!terms) return SAMPLE;
        const replace = makeReplacer(terms.map(term => ({ ...term, own: draft[term.key]?.singular ? draft[term.key] : null })));
        return replace(SAMPLE);
    }, [terms, draft]);

    const change = (key, field) => (event) =>
        setDraft(previous => ({ ...previous, [key]: { ...previous[key], [field]: event.target.value } }));

    const reset = (key) =>
        setDraft(previous => ({ ...previous, [key]: { singular: "", plural: "" } }));

    const save = async () => {
        setSaving(true);
        setError("");
        setSaved("");
        try {
            const response = await axiosClient.put("/terminology", { terms: draft });
            const list = response.data.data;
            setRows(list);
            // the screens use the new words at once
            setTerms(list);
            setSaved("Saved. The new words are used everywhere now (screens, reports and exports).");
        }
        catch (saveError) {
            setError(getApiErrorMessage(saveError, "The wording could not be saved."));
        }
        finally {
            setSaving(false);
        }
    };

    const header = (
        <PageHeader
            title="Wording"
            subtitle="Call things the way your organization does (for example Fund, Administrator). Leave a box empty to keep the default word."
        />
    );

    if (!terms) {
        return (
            <PageContainer>
                {header}
                {error ? <ErrorState message={error} /> : <LoadingState message="Loading..." />}
            </PageContainer>
        );
    }

    const groups = [...new Set(terms.map(term => term.group))];

    return (
        <PageContainer>

            {header}

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
            {saved && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSaved("")}>{saved}</Alert>}

            <PageCard>
                <FormSection title="Preview">
                    <Typography sx={{ fontFamily: "monospace" }}>{preview}</Typography>
                </FormSection>
            </PageCard>

            {groups.map(group => (
                <PageCard key={group}>
                    <FormSection
                        title={group}
                        subtitle={group === "Statuses" ? "Only the label shown is renamed (status boxes, status choices, report status columns). Each status keeps its meaning and rules." : undefined}
                    >
                        <Stack spacing={1.5}>
                            {terms.filter(term => term.group === group).map(term => (
                                <Box key={term.key} sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "220px 1fr 1fr auto" }, gap: 1.5, alignItems: "center" }}>
                                    <Box>
                                        <Typography sx={{ fontWeight: 600 }}>{term.singular}</Typography>
                                        {!term.status && <Typography variant="caption" color="text.secondary">plural: {term.plural}</Typography>}
                                    </Box>
                                    <WordBox label={`Your word for "${term.singular}"`} value={draft[term.key]?.singular || ""} onChange={change(term.key, "singular")} />
                                    {term.status
                                        ? <Box />
                                        : <WordBox label={`Plural ("${term.plural}")`} value={draft[term.key]?.plural || ""} onChange={change(term.key, "plural")} />}
                                    <AppButton size="small" variant="text" startIcon={<Restore />} onClick={() => reset(term.key)} disabled={!draft[term.key]?.singular && !draft[term.key]?.plural}>
                                        Default
                                    </AppButton>
                                </Box>
                            ))}
                        </Stack>
                    </FormSection>
                </PageCard>
            ))}

            <Stack direction="row" sx={{ justifyContent: "flex-end", mb: 5 }}>
                <AppButton variant="contained" startIcon={<Save />} onClick={save} loading={saving}>
                    Save Wording
                </AppButton>
            </Stack>

        </PageContainer>
    );

};


// the boxes show the words exactly as typed (not translated)
const WordBox = ({ label, value, onChange }) => (
    <Box>
        <Typography variant="caption" color="text.secondary">{label}</Typography>
        <input
            value={value}
            onChange={onChange}
            maxLength={40}
            style={{ width: "100%", padding: "8px 10px", border: "1px solid #cbd5e1", borderRadius: 6, font: "inherit" }}
        />
    </Box>
);


export default WordingPage;
