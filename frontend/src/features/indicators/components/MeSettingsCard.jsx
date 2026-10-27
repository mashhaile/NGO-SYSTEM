import { useState } from "react";

import {
    Alert,
    Box,
    IconButton,
    Paper,
    Stack,
    TextField,
    Tooltip,
    Typography
} from "@mui/material";
import { RestartAlt, Save, Tune } from "@mui/icons-material";

import { getApiErrorMessage } from "../../../utils/apiError";

import { updateMeSettingsApi } from "../api/indicatorApi";
import { DEFAULT_LIMITS } from "../utils/indicatorUtils";


// =====================================================
// M&E SETTINGS (organization admin)
// =====================================================
//
// When an indicator is on track, at risk or off track, as %
// of its target achieved. Applies at once to every
// indicator, page and report; nothing is recalculated or
// stored. The circular-arrow icon sets the defaults back.
//
// =====================================================

const MeSettingsCard = ({ limits, onChange }) => {

    const [draft, setDraft] = useState(null);
    const [error, setError] = useState("");
    const [saved, setSaved] = useState("");
    const [saving, setSaving] = useState(false);

    const shown = draft || { onTrack: String(limits.onTrack), atRisk: String(limits.atRisk) };
    const changed = Boolean(draft) && (Number(draft.onTrack) !== limits.onTrack || Number(draft.atRisk) !== limits.atRisk);
    const isDefault = limits.onTrack === DEFAULT_LIMITS.onTrack && limits.atRisk === DEFAULT_LIMITS.atRisk;

    const send = async (data, message) => {
        setError("");
        setSaved("");
        setSaving(true);
        try {
            const settings = await updateMeSettingsApi(data);
            onChange({ onTrack: settings.onTrack, atRisk: settings.atRisk });
            setDraft(null);
            setSaved(message);
        }
        catch (saveError) {
            setError(getApiErrorMessage(saveError, "The settings could not be saved."));
        }
        finally {
            setSaving(false);
        }
    };

    const save = () => {
        const onTrack = Number(shown.onTrack);
        const atRisk = Number(shown.atRisk);
        if (![onTrack, atRisk].every(value => value >= 1 && value <= 100)) return setError("Both limits must be between 1 and 100.");
        if (atRisk >= onTrack) return setError("\"At risk from\" must be lower than \"On track from\".");
        return send({ onTrack, atRisk }, "Saved. Every indicator, page and report uses the new limits.");
    };

    return (
        <Paper variant="outlined" sx={{ p: 2, mb: 2, borderRadius: 3 }}>

            <Stack direction={{ xs: "column", md: "row" }} spacing={2} sx={{ alignItems: { md: "center" } }}>

                <Stack direction="row" spacing={1} sx={{ alignItems: "center", flex: 1, minWidth: 0 }}>
                    <Tune color="primary" />
                    <Box>
                        <Typography sx={{ fontWeight: 700 }}>M&amp;E settings</Typography>
                        <Typography variant="body2" color="text.secondary">
                            When an indicator counts as on track or at risk (% of its target achieved). Below &quot;at risk&quot;: off track.
                        </Typography>
                    </Box>
                </Stack>

                <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
                    <TextField
                        size="small"
                        type="number"
                        label="On track from (%)"
                        value={shown.onTrack}
                        onChange={(event) => setDraft({ ...shown, onTrack: event.target.value })}
                        inputProps={{ min: 1, max: 100 }}
                        sx={{ width: 150 }}
                    />
                    <TextField
                        size="small"
                        type="number"
                        label="At risk from (%)"
                        value={shown.atRisk}
                        onChange={(event) => setDraft({ ...shown, atRisk: event.target.value })}
                        inputProps={{ min: 1, max: 100 }}
                        sx={{ width: 140 }}
                    />
                    <Tooltip title="Save">
                        <span>
                            <IconButton color="primary" onClick={save} disabled={!changed || saving} aria-label="Save the M&E settings">
                                <Save />
                            </IconButton>
                        </span>
                    </Tooltip>
                    <Tooltip title={`Set to default (on track from ${DEFAULT_LIMITS.onTrack}%, at risk from ${DEFAULT_LIMITS.atRisk}%)`}>
                        <span>
                            <IconButton
                                onClick={() => send({ reset: true }, `Back to the defaults: on track from ${DEFAULT_LIMITS.onTrack}%, at risk from ${DEFAULT_LIMITS.atRisk}%.`)}
                                disabled={(isDefault && !draft) || saving}
                                aria-label="Set the M&E settings to default"
                            >
                                <RestartAlt />
                            </IconButton>
                        </span>
                    </Tooltip>
                </Stack>

            </Stack>

            {/* the three statuses the two limits make, as typed */}
            {(() => {
                const onTrack = Number(shown.onTrack);
                const atRisk = Number(shown.atRisk);
                const valid = onTrack >= 1 && onTrack <= 100 && atRisk >= 1 && atRisk < onTrack;
                return (
                    <Typography variant="body2" sx={{ mt: 1.5, color: valid ? "text.secondary" : "error.main" }}>
                        {valid
                            ? `🟢 On track: ${onTrack}% and above  ·  🟡 At risk: ${atRisk}–${onTrack - 1}%  ·  🔴 Off track: below ${atRisk}%`
                            : "\"At risk from\" must be lower than \"On track from\", both between 1 and 100."}
                    </Typography>
                );
            })()}

            {error && <Alert severity="error" sx={{ mt: 1.5 }}>{error}</Alert>}
            {saved && <Alert severity="success" sx={{ mt: 1.5 }} onClose={() => setSaved("")}>{saved}</Alert>}

        </Paper>
    );

};

export default MeSettingsCard;
