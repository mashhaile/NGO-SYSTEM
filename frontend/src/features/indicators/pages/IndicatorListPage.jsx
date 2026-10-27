import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { Alert, Box, Link, Typography } from "@mui/material";
import { Add } from "@mui/icons-material";

import {
    DataTable,
    PageCard,
    PageContainer,
    PageHeader,
    SearchToolbar,
    StatusChip
} from "../../../components/ui";

import useAuth from "../../auth/hooks/useAuth";
import { getApiErrorMessage } from "../../../utils/apiError";

import { getIndicatorsApi, getProgramOptionsApi } from "../api/indicatorApi";
import { LEVELS, nameOf, percentText, periodLabel, statusHelp, valueText } from "../utils/indicatorUtils";
import { useMeLimits } from "../indicatorHooks";
import MeSettingsCard from "../components/MeSettingsCard";


// =====================================================
// M&E: INDICATORS
// =====================================================
//
// Every indicator with its latest period that has started:
// target, actual, % achieved and status. Open one to see
// all its periods and enter values.
//
// =====================================================

const toOptions = (values) => values.map(value => ({ value, label: value }));


const IndicatorListPage = () => {

    const navigate = useNavigate();
    const { user } = useAuth();
    const permissions = user?.permissions || [];
    const canCreate = permissions.includes("*") || permissions.includes("indicator.create");
    // the organization admin sets the on track / at risk limits
    const canSet = permissions.includes("*") || permissions.includes("organization.update");
    const [limits, setLimits] = useMeLimits();

    const [rows, setRows] = useState([]);
    const [programs, setPrograms] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [search, setSearch] = useState("");
    const [program, setProgram] = useState("");
    const [level, setLevel] = useState("");

    useEffect(() => {
        getProgramOptionsApi().then(setPrograms).catch(() => setPrograms([]));
    }, []);

    useEffect(() => {
        let alive = true;
        const timer = setTimeout(() => {
            setLoading(true);
            getIndicatorsApi({ search: search || undefined, program: program || undefined, level: level || undefined })
                .then(list => { if (alive) { setRows(list); setError(""); } })
                .catch(loadError => { if (alive) setError(getApiErrorMessage(loadError, "The indicators could not be loaded.")); })
                .finally(() => { if (alive) setLoading(false); });
        }, search ? 300 : 0);
        return () => { alive = false; clearTimeout(timer); };
    }, [search, program, level, limits]);

    const columns = [
        {
            field: "name",
            headerName: "Indicator",
            flex: 1.6,
            minWidth: 220,
            renderCell: (params) => (
                <Box sx={{ py: 1 }}>
                    <Link component="button" underline="hover" sx={{ fontWeight: 600, textAlign: "left" }} onClick={() => navigate(`/indicators/${params.row._id}`)}>
                        {params.row.name}
                    </Link>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        {params.row.code} · {params.row.level}{params.row.result ? ` · ${params.row.result}` : ""}
                    </Typography>
                </Box>
            )
        },
        {
            field: "program",
            headerName: "Program / Project",
            flex: 1,
            minWidth: 150,
            renderCell: (params) => (
                <Box sx={{ py: 1 }}>
                    <Typography variant="body2">{nameOf(params.row.program)}</Typography>
                    <Typography variant="caption" color="text.secondary">{params.row.project ? nameOf(params.row.project) : "Whole program"}</Typography>
                </Box>
            )
        },
        {
            field: "source",
            headerName: "Source",
            minWidth: 95,
            valueGetter: (value, row) => (row.source === "auto" ? "Automatic" : "Entered")
        },
        {
            field: "period",
            headerName: "Period",
            minWidth: 90,
            valueGetter: (value, row) => (row.current ? periodLabel(row.current.period) : "-")
        },
        {
            field: "target",
            headerName: "Target",
            minWidth: 80,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) => valueText(row.current?.target, row.unit)
        },
        {
            field: "actual",
            headerName: "Actual",
            minWidth: 80,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) => valueText(row.current?.actual, row.unit)
        },
        {
            field: "percent",
            headerName: "Achieved",
            minWidth: 90,
            align: "right",
            headerAlign: "right",
            valueGetter: (value, row) => percentText(row.current?.percent)
        },
        {
            field: "status",
            headerName: "Status",
            minWidth: 110,
            renderCell: (params) => <StatusChip status={params.row.current?.status || "No data"} />
        }
    ];

    return (
        <PageContainer>

            <PageHeader
                title="Indicators"
                subtitle={`M&E: each program's and project's indicators against their targets. ${statusHelp(limits)}`}
                action={canCreate ? () => navigate("/indicators/create") : undefined}
                actionLabel="New Indicator"
                actionIcon={<Add />}
            />

            {canSet && <MeSettingsCard limits={limits} onChange={setLimits} />}

            <SearchToolbar
                search={search}
                onSearch={setSearch}
                onReset={() => { setSearch(""); setProgram(""); setLevel(""); }}
                filters={[
                    { key: "program", label: "Program", value: program, onChange: setProgram, options: programs.map(item => ({ value: item._id, label: nameOf(item) })) },
                    { key: "level", label: "Level", value: level, onChange: setLevel, options: toOptions(LEVELS) }
                ]}
            />

            {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

            <PageCard>
                <DataTable
                    rows={rows}
                    columns={columns}
                    loading={loading}
                    getRowHeight={() => "auto"}
                    onRowDoubleClick={(params) => navigate(`/indicators/${params.row._id}`)}
                />
            </PageCard>

        </PageContainer>
    );

};

export default IndicatorListPage;
