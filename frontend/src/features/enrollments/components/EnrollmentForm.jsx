import { useEffect, useState } from "react";

import {
    Box,
    Grid,
    TextField,
    MenuItem,
    Button,
    Stack,
    Autocomplete
} from "@mui/material";

import { Save } from "@mui/icons-material";

import {
    getProgramsLookupService,
    getBeneficiariesLookupService
} from "../services/lookupService";

const initialState = {
    program: null,
    beneficiary: null,
    enrollmentDate: "",
    status: "Pending",
    completionDate: "",
    exitReason: "",
    remarks: ""
};

const EnrollmentForm = ({
    initialData = {},
    onSubmit,
    loading = false
}) => {

    const [formData, setFormData] = useState(initialState);

    const [programs, setPrograms] = useState([]);

    const [beneficiaries, setBeneficiaries] = useState([]);

    useEffect(() => {
        loadLookups();
    }, []);

    useEffect(() => {

        if (initialData && Object.keys(initialData).length) {

            setFormData({

                program: initialData.program || null,

                beneficiary: initialData.beneficiary || null,

                enrollmentDate: initialData.enrollmentDate
                    ? initialData.enrollmentDate.substring(0, 10)
                    : "",

                status: initialData.status || "Pending",

                completionDate: initialData.completionDate
                    ? initialData.completionDate.substring(0, 10)
                    : "",

                exitReason: initialData.exitReason || "",

                remarks: initialData.remarks || ""

            });

        }

    }, [initialData]);

    const loadLookups = async () => {

        try {

            const [
                programData,
                beneficiaryData
            ] = await Promise.all([
                getProgramsLookupService(),
                getBeneficiariesLookupService()
            ]);


            setPrograms(programData || []);
            setBeneficiaries(beneficiaryData || []);

        } catch (error) {

            console.error("Lookup loading error:", error);

        }

    };

    const changeField = (field, value) => {

        setFormData(prev => ({
            ...prev,
            [field]: value
        }));

    };

    const submitHandler = (e) => {

        e.preventDefault();

        const payload = {

            program: formData.program?._id,

            beneficiary: formData.beneficiary?._id,

            enrollmentDate: formData.enrollmentDate,

            status: formData.status,

            completionDate: formData.completionDate || null,

            exitReason: formData.exitReason || "",

            remarks: formData.remarks || ""

        };


        onSubmit(payload);

    };

    return (

        <Box
            component="form"
            onSubmit={submitHandler}
        >

            <Grid container spacing={3}>

               <Grid size={{xs:12,md:6}}>

    <Autocomplete

        options={programs}

        value={formData.program}

        getOptionLabel={(option)=>
            option
            ?
            `${option.programCode} - ${option.name}`
            :
            ""
        }

        isOptionEqualToValue={(option,value)=>
            option?._id === value?._id
        }

        onChange={(e,value)=>
            changeField(
                "program",
                value
            )
        }

        renderInput={(params)=>(

            <TextField

                {...params}

                label="Program"

                required

            />

        )}

    />

</Grid>

                <Grid size={{xs:12,md:6}}>

    <Autocomplete

        options={beneficiaries}

        value={formData.beneficiary}

        getOptionLabel={(option)=>
            option
            ?
            `${option.beneficiaryNumber} - ${option.fullName}`
            :
            ""
        }

        isOptionEqualToValue={(option,value)=>
            option?._id === value?._id
        }

        onChange={(e,value)=>
            changeField(
                "beneficiary",
                value
            )
        }

        renderInput={(params)=>(

            <TextField

                {...params}

                label="Beneficiary"

                required

            />

        )}

    />

</Grid>

                <Grid
                    size={{ xs: 12, md: 6 }}>

                    <TextField
                        fullWidth
                        type="date"
                        label="Enrollment Date"
                        InputLabelProps={{
                            shrink: true
                        }}
                        value={formData.enrollmentDate}
                        onChange={(e) =>
                            changeField(
                                "enrollmentDate",
                                e.target.value
                            )
                        }
                    />

                </Grid>

                <Grid
                    size={{ xs: 12, md: 6 }}>

                    <TextField
                        select
                        fullWidth
                        label="Status"
                        value={formData.status}
                        onChange={(e) =>
                            changeField(
                                "status",
                                e.target.value
                            )
                        }
                    >

                        {[
                            "Pending",
                            "Active",
                            "Completed",
                            "Dropped"
                        ].map(status => (

                            <MenuItem
                                key={status}
                                value={status}
                            >
                                {status}
                            </MenuItem>

                        ))}

                    </TextField>

                </Grid>

                <Grid
                    size={{ xs: 12 }}>

                    <TextField
                        fullWidth
                        multiline
                        rows={3}
                        label="Remarks"
                        value={formData.remarks}
                        onChange={(e) =>
                            changeField(
                                "remarks",
                                e.target.value
                            )
                        }
                    />

                </Grid>

            </Grid>

            <Stack
                direction="row"
                justifyContent="flex-end"
                mt={3}
            >

                <Button
                    variant="contained"
                    type="submit"
                    startIcon={<Save />}
                    disabled={loading}
                >

                    {loading
                        ? "Saving..."
                        : "Save Enrollment"}

                </Button>

            </Stack>

        </Box>

    );

};

export default EnrollmentForm;