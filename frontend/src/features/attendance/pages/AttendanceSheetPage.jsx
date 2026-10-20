import {
    useEffect,
    useState
} from "react";

import {
    useParams,
    useNavigate
}
from "react-router-dom";

import {
    useDispatch,
    useSelector
}
from "react-redux";

import {
    Button,
    Stack,
    CircularProgress,
    Typography,
    Box
}
from "@mui/material";

import {
    ArrowBack,
    Save
}
from "@mui/icons-material";

import {
    PageContainer,
    PageHeader,
    StatsCards,
    PageCard
}
from "../../../components/ui";

import ParticipantSelector
from "../components/ParticipantSelector";

import AttendanceGrid
from "../components/AttendanceGrid";

import {
    getAttendanceByIdThunk,
    getAttendanceRecordsThunk,
    saveAttendanceRecordsThunk
}
from "../store";

const participantTypes = [

    "Beneficiary",

    "Staff",

    "Board",

    "Partner",

    "Government",

    "Community",

    "Other"

];

const externalParticipantTypes = [

    "Board",

    "Partner",

    "Government",

    "Community",

    "Other"

];

const AttendanceSheetPage = () => {

    const { id } = useParams();

    const navigate = useNavigate();

    const dispatch = useDispatch();

    const {
        loading
    } = useSelector(
        state => state.attendance
    );

    const [
        attendance,
        setAttendance
    ] = useState(null);

    const [
        rows,
        setRows
    ] = useState([]);

    const [
        type,
        setType
    ] = useState(
        "Beneficiary"
    );

    useEffect(() => {

        loadAttendance();

    }, [id]);

    const loadAttendance = async () => {

        try {

            const session =
                await dispatch(
                    getAttendanceByIdThunk(id)
                ).unwrap();

            setAttendance(session);

            const records =
                await dispatch(
                    getAttendanceRecordsThunk(id)
                ).unwrap();

            setRows(

                (
                    Array.isArray(records)
                        ? records
                        : []
                ).map(item => ({

                    id: item._id,

                    ...item

                }))

            );

        }
        catch (error) {

            console.error(
                "Attendance load error",
                error
            );

        }

    };

    const getExternalParticipantKey = (
        participant
    ) => {

        const external =
            participant?.externalParticipant || {};

        const name =
            external.name || "";

        const organizationName =
            external.organizationName || "";

        const position =
            external.position || "";

        const phone =
            external.phone || "";

        const email =
            external.email || "";

        return [

            participant?.participantType || "",

            name.trim().toLowerCase(),

            organizationName.trim().toLowerCase(),

            position.trim().toLowerCase(),

            phone.trim(),

            email.trim().toLowerCase()

        ].join("|");

    };

    const addParticipant = (person) => {

        const participantType =
            person.participantType ||
            type;

        const exists = rows.some(row => {

            if (
                participantType ===
                "Beneficiary"
            ) {

                return (

                    (
                        row.beneficiary?._id ||
                        row.beneficiary
                    )

                    ===

                    (
                        person.beneficiary?._id ||
                        person.beneficiary
                    )

                );

            }

            if (
                participantType ===
                "Staff"
            ) {

                return (

                    (
                        row.staff?._id ||
                        row.staff
                    )

                    ===

                    (
                        person.staff?._id ||
                        person.staff
                    )

                );

            }

            if (
                externalParticipantTypes.includes(
                    participantType
                )
            ) {

                return (

                    getExternalParticipantKey(
                        row
                    )

                    ===

                    getExternalParticipantKey({
                        ...person,
                        participantType
                    })

                );

            }

            return false;

        });

        if (exists) {

            alert(
                "Participant already exists"
            );

            return;

        }

        setRows(prev => [

            ...prev,

            {

                id: Date.now(),

                ...person,

                participantType,

                gender:
                    person.gender ||
                    person.externalParticipant?.gender ||
                    null,

                ageGroup:
                    person.ageGroup ||
                    null,

                location:
                    person.location ||
                    null,

                disabilityStatus:
                    person.disabilityStatus ||
                    false,

                status:
                    person.status ||
                    "Present"

            }

        ]);

    };

    const saveAttendance = async () => {

        try {

            const data =
                rows.map(row => {

                    const participantType =
                        row.participantType;

                    const isBeneficiary =
                        participantType ===
                        "Beneficiary";

                    const isStaff =
                        participantType ===
                        "Staff";

                    const isExternal =
                        externalParticipantTypes.includes(
                            participantType
                        );

                    return {

                        participantType,

                        beneficiary:
                            isBeneficiary
                                ? (
                                    row.beneficiary?._id ||
                                    row.beneficiary ||
                                    null
                                )
                                : null,

                        staff:
                            isStaff
                                ? (
                                    row.staff?._id ||
                                    row.staff ||
                                    null
                                )
                                : null,

                        externalParticipant:
                            isExternal
                                ? (
                                    row.externalParticipant ||
                                    null
                                )
                                : null,

                        gender:
                            row.gender ||
                            null,

                        ageGroup:
                            row.ageGroup ||
                            null,

                        location:
                            row.location ||
                            null,

                        disabilityStatus:
                            row.disabilityStatus ||
                            false,

                        status:
                            row.status ||
                            "Present",

                        notes:
                            row.notes ||
                            null

                    };

                });


            await dispatch(

                saveAttendanceRecordsThunk({

                    id,

                    data

                })

            ).unwrap();

            navigate(
                "/attendance"
            );

        }
        catch (error) {

            console.error(
                "Save Attendance Error",
                error
            );

            alert(

                error?.message ||

                "Save failed"

            );

        }

    };

    if (!attendance) {

        return (

            <PageContainer>

                <PageCard>

                    <CircularProgress />

                </PageCard>

            </PageContainer>

        );

    }

    return (

        <PageContainer>

            <PageHeader

                title="Attendance Sheet"

                subtitle={

                    `${attendance.activityRun?.runCode || ""} • ${attendance.sessionTitle}`

                }

                action={() =>
                    navigate("/attendance")
                }

                actionLabel="Back"

                actionIcon={<ArrowBack />}

            />

            <StatsCards

                items={[

                    {

                        label:
                            "Total Participants",

                        value:
                            rows.length

                    },

                    {

                        label:
                            "Present",

                        value:
                            rows.filter(
                                x =>
                                    x.status ===
                                    "Present"
                            ).length

                    },

                    {

                        label:
                            "Absent",

                        value:
                            rows.filter(
                                x =>
                                    x.status ===
                                    "Absent"
                            ).length

                    },

                    {

                        label:
                            "Late",

                        value:
                            rows.filter(
                                x =>
                                    x.status ===
                                    "Late"
                            ).length

                    }

                ]}

            />

            <PageCard>

                <Typography
                    fontWeight={700}
                    mb={2}
                >

                    Participant Type

                </Typography>

                <Stack sx={{ flexWrap: "wrap" }}

                    direction="row"

                    spacing={1}

                    useFlexGap

                >

                    {
                        participantTypes.map(
                            item => (

                                <Button

                                    key={item}

                                    variant={

                                        type === item

                                            ? "contained"

                                            : "outlined"

                                    }

                                    onClick={() =>
                                        setType(item)
                                    }

                                >

                                    {item}

                                </Button>

                            )
                        )
                    }

                </Stack>

            </PageCard>

            <Box

                sx={{

                    width: {

                        xs: "100%",

                        md: "75%"

                    }

                }}

            >

                <PageCard>

                    <Typography

                        fontWeight={700}

                        mb={2}

                    >

                        Add Participant

                    </Typography>

                    <ParticipantSelector

                        type={type}

                        onAdd={addParticipant}

                    />

                </PageCard>

            </Box>

            <PageCard>

                <Typography

                    fontWeight={700}

                    mb={2}

                >

                    Attendance Records

                </Typography>

                <AttendanceGrid

                    rows={rows}

                    setRows={setRows}

                />

            </PageCard>

            <Box

                sx={{

                    display: "flex",

                    justifyContent: "center",

                    alignItems: "center"

                }}

            >

                <Button

                    variant="contained"

                    startIcon={<Save />}

                    disabled={loading}

                    onClick={saveAttendance}

                >

                    {

                        loading

                            ? "Saving..."

                            : "Save Attendance"

                    }

                </Button>

            </Box>

        </PageContainer>

    );

};

export default AttendanceSheetPage;