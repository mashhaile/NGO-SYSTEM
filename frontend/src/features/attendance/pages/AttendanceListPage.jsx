import {
    useEffect,
    useState
} from "react";

import {
    useNavigate
} from "react-router-dom";

import {
    Alert,
    Box,
    Link,
    Typography
} from "@mui/material";

import {
    Add,
    Delete,
    Edit,
    FactCheck
} from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    PageCard,
    SearchToolbar,
    DataTable,
    AppIconButton,
    ConfirmDeleteDialog
} from "../../../components/ui";

import useAuth
    from "../../auth/hooks/useAuth";

import useServerList
    from "../../../hooks/useServerList";

import {
    getAttendancesApi,
    deleteAttendanceApi
} from "../api/attendanceApi";

import {
    getProgramsLookupApi
} from "../../programs/api/lookupApi";

import { hasPermission } from "../../../utils/permissions";
import { getApiErrorMessage } from "../../../utils/apiError";


const twoLine = (main, caption) => (
    <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
        <Typography variant="body2">{main || "-"}</Typography>
        {caption && (
            <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                {caption}
            </Typography>
        )}
    </Box>
);


// =====================================================
// ATTENDANCE LIST PAGE
// =====================================================

const AttendanceListPage = () => {

    const navigate = useNavigate();

    const { user } = useAuth();

    const [search, setSearch] = useState("");
    const [program, setProgram] = useState("");
    const [programOptions, setProgramOptions] = useState([]);

    const [deleteTarget, setDeleteTarget] = useState(null);
    const [deleting, setDeleting] = useState(false);

    const list = useServerList(getAttendancesApi, { search, program }, "Failed to load attendance sessions.");


    useEffect(() => {
        getProgramsLookupApi()
            .then(({ data }) => setProgramOptions(
                (data?.data || []).map(item => ({ value: item._id, label: item.name }))
            ))
            .catch(() => setProgramOptions([]));
    }, []);


    const handleDelete = async () => {

        setDeleting(true);

        try {
            await deleteAttendanceApi(deleteTarget._id);
            setDeleteTarget(null);
            list.reload();
        }
        catch (error) {
            setDeleteTarget(null);
            list.setError(getApiErrorMessage(error, "Failed to delete the session."));
        }
        finally {
            setDeleting(false);
        }

    };


    const canUpdate = hasPermission(user, "attendance.update");
    const canDelete = hasPermission(user, "attendance.delete");

    const filterChange = (setter) => (value) => { setter(value); list.resetPage(); };

    const sheetUrl = (row) => `/attendance/${row._id}/sheet`;


    const columns = [

        {
            field: "sessionTitle",
            headerName: "Session",
            flex: 1.4,
            minWidth: 230,
            renderCell: (params) => (
                <Box sx={{ lineHeight: 1.3, py: 0.5, minWidth: 0 }}>
                    <Link
                        component="button"
                        underline="hover"
                        sx={{ fontWeight: 600, textAlign: "left" }}
                        onClick={() => navigate(sheetUrl(params.row))}
                    >
                        {params.value || `Session ${params.row.sessionNumber || ""}`}
                    </Link>
                    <Typography variant="caption" sx={{ color: "text.secondary", display: "block" }}>
                        {params.row.sessionNumber ? `Session ${params.row.sessionNumber}` : ""}
                    </Typography>
                </Box>
            )
        },

        {
            field: "sessionDate",
            headerName: "Date",
            minWidth: 110,
            valueGetter: (value) => (value ? new Date(value).toLocaleDateString() : "-")
        },

        {
            field: "activityRun",
            headerName: "Activity Run",
            flex: 1.4,
            minWidth: 230,
            sortable: false,
            renderCell: (params) => twoLine(params.row.activityRun?.name, params.row.activityRun?.runCode)
        },

        {
            field: "project",
            headerName: "Project",
            flex: 1.1,
            minWidth: 180,
            sortable: false,
            renderCell: (params) => twoLine(params.row.project?.name, params.row.program?.name)
        },

        {
            field: "actions",
            headerName: "Actions",
            width: 140,
            sortable: false,
            filterable: false,
            disableColumnMenu: true,
            renderCell: (params) => (
                <>
                    <AppIconButton
                        icon={<FactCheck fontSize="small" />}
                        tooltip="Attendance sheet"
                        onClick={() => navigate(sheetUrl(params.row))}
                    />
                    {canUpdate && (
                        <AppIconButton
                            icon={<Edit fontSize="small" />}
                            tooltip="Edit session"
                            onClick={() => navigate(`/attendance/${params.row._id}/edit`)}
                        />
                    )}
                    {canDelete && (
                        <AppIconButton
                            icon={<Delete fontSize="small" />}
                            tooltip="Delete session"
                            color="error"
                            onClick={() => setDeleteTarget(params.row)}
                        />
                    )}
                </>
            )
        }

    ];


    return (

        <PageContainer>

            <PageHeader
                title="Attendance"
                subtitle="Attendance sessions of activity runs. Open a session's sheet to mark who attended."
                {...(
                    hasPermission(user, "attendance.create")
                        ? {
                            action: () => navigate("/attendance/create"),
                            actionLabel: "Create Attendance",
                            actionIcon: <Add />
                        }
                        : {}
                )}
            />

            <SearchToolbar
                search={search}
                onSearch={filterChange(setSearch)}
                onReset={() => {
                    setSearch("");
                    setProgram("");
                    list.resetPage();
                }}
                filters={[
                    { key: "program", label: "Program", value: program, onChange: filterChange(setProgram), options: programOptions }
                ]}
            />

            {list.error && (
                <Alert severity="error" sx={{ mb: 3 }}>
                    {list.error}
                </Alert>
            )}

            <PageCard>
                <DataTable
                    rows={list.rows}
                    columns={columns}
                    loading={list.loading}
                    paginationMode="server"
                    rowCount={list.total}
                    paginationModel={list.paginationModel}
                    onPaginationModelChange={list.setPaginationModel}
                    getRowHeight={() => "auto"}
                    onRowDoubleClick={(params) => navigate(sheetUrl(params.row))}
                />
            </PageCard>

            <ConfirmDeleteDialog
                open={Boolean(deleteTarget)}
                title="Delete Session"
                message={
                    deleteTarget
                        ? `Delete session "${deleteTarget.sessionTitle || deleteTarget.sessionNumber}"? This cannot be undone.`
                        : ""
                }
                loading={deleting}
                onClose={() => !deleting && setDeleteTarget(null)}
                onConfirm={handleDelete}
            />

        </PageContainer>

    );

};


export default AttendanceListPage;
