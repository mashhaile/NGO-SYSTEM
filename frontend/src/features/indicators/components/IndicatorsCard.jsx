import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Box, Link, Typography } from "@mui/material";
import { Add } from "@mui/icons-material";

import { AppButton, FormSection, PageCard, StatusChip } from "../../../components/ui";

import useAuth from "../../auth/hooks/useAuth";
import { useModuleOn } from "../../../utils/modules";

import { getIndicatorsApi } from "../api/indicatorApi";
import { percentText, periodLabel, valueText } from "../utils/indicatorUtils";


// =====================================================
// INDICATORS OF A PROGRAM / PROJECT (its page)
// =====================================================
// Shown only when the M&E module is on and the user may see
// indicators. A program shows its own and its projects'.

const IndicatorsCard = ({ program, project }) => {

    const navigate = useNavigate();
    const { user } = useAuth();
    const meOn = useModuleOn("me");
    const permissions = user?.permissions || [];
    const canRead = permissions.includes("*") || permissions.includes("indicator.read");
    const canCreate = permissions.includes("*") || permissions.includes("indicator.create");

    const [rows, setRows] = useState(null);

    useEffect(() => {
        if (!meOn || !canRead || (!program && !project)) return undefined;
        let alive = true;
        getIndicatorsApi(project ? { project } : { program })
            .then(list => { if (alive) setRows(list); })
            .catch(() => { if (alive) setRows([]); });
        return () => { alive = false; };
    }, [meOn, canRead, program, project]);

    if (!meOn || !canRead) return null;

    const newLink = `/indicators/create?program=${program || ""}${project ? `&project=${project}` : ""}`;

    return (
        <PageCard>
            <FormSection
                title="Indicators (M&E)"
                subtitle="Targets against actual values, for each indicator's latest reported period."
            >
                {rows === null && <Typography color="text.secondary">Loading...</Typography>}

                {rows && rows.length === 0 && (
                    <Typography color="text.secondary" sx={{ mb: 1 }}>No indicators yet.</Typography>
                )}

                {rows && rows.length > 0 && (
                    <Box sx={{ display: "grid", gap: 1 }}>
                        {rows.map(row => (
                            <Box
                                key={row._id}
                                sx={{
                                    display: "grid",
                                    gridTemplateColumns: { xs: "1fr", md: "2fr 1fr 1fr auto" },
                                    gap: 1,
                                    alignItems: "center",
                                    py: 1,
                                    borderBottom: "1px solid",
                                    borderColor: "divider"
                                }}
                            >
                                <Box>
                                    <Link component="button" underline="hover" sx={{ fontWeight: 600, textAlign: "left" }} onClick={() => navigate(`/indicators/${row._id}`)}>
                                        {row.name}
                                    </Link>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                        {row.code} · {row.level}{!project && row.project ? ` · ${row.project.name}` : ""}
                                    </Typography>
                                </Box>
                                <Typography variant="body2">
                                    {row.current ? `${periodLabel(row.current.period)}: ${valueText(row.current.actual, row.unit)} of ${valueText(row.current.target, row.unit)}` : "No period started"}
                                </Typography>
                                <Typography variant="body2" sx={{ fontWeight: 700 }}>{percentText(row.current?.percent)}</Typography>
                                <StatusChip status={row.current?.status || "No data"} />
                            </Box>
                        ))}
                    </Box>
                )}

                {canCreate && (
                    <AppButton variant="text" startIcon={<Add />} onClick={() => navigate(newLink)} sx={{ mt: 1 }}>
                        Add Indicator
                    </AppButton>
                )}
            </FormSection>
        </PageCard>
    );

};

export default IndicatorsCard;
