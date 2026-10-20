import {
    useState
} from "react";

import {
    useSelector
} from "react-redux";

import {
    useNavigate
} from "react-router-dom";

import {
    Button,
    Stack,
    Typography,
    Alert
} from "@mui/material";

import {
    UploadFile,
    Download,
    ArrowBack
} from "@mui/icons-material";

import {
    PageCard,
    LoadingState
} from "../../../components/ui";

import {
    importBeneficiariesService,
    downloadBeneficiaryTemplateService
} from "../services/beneficiaryImportService";

import {
    selectSelectedOrganizationId
} from "../../superadmin/store/organizationContextSlice";


const BeneficiaryImport = () => {

    const navigate = useNavigate();


    // =====================================
    // ORGANIZATION CONTEXT
    // =====================================

    const selectedOrganizationId =
        useSelector(
            selectSelectedOrganizationId
        );


    // =====================================
    // LOCAL STATE
    // =====================================

    const [file, setFile] =
        useState(null);

    const [loading, setLoading] =
        useState(false);

    const [message, setMessage] =
        useState("");

    const [error, setError] =
        useState("");


    // =====================================
    // SELECT FILE
    // =====================================

    const handleFileChange = (event) => {

        const selectedFile =
            event.target.files?.[0] || null;

        setMessage("");
        setError("");


        if (!selectedFile) {

            setFile(null);

            return;

        }


        // =====================================
        // VALIDATE FILE TYPE
        // =====================================

        const fileName =
            String(
                selectedFile.name || ""
            )
                .trim()
                .toLowerCase();


        if (
            !fileName.endsWith(".xlsx")
        ) {

            setFile(null);

            setError(
                "Please select a valid Excel .xlsx file."
            );

            return;

        }


        // =====================================
        // VALIDATE FILE SIZE
        // Backend limit: 10 MB
        // =====================================

        const maxSize =
            10 * 1024 * 1024;


        if (
            selectedFile.size > maxSize
        ) {

            setFile(null);

            setError(
                "The selected file exceeds the 10 MB limit."
            );

            return;

        }


        setFile(
            selectedFile
        );

    };


    // =====================================
    // IMPORT
    // =====================================

    const handleImport = async () => {

        setMessage("");
        setError("");


        // =====================================
        // ORGANIZATION
        // =====================================

        if (!selectedOrganizationId) {

            setError(
                "Please select an organization before importing beneficiaries."
            );

            return;

        }


        // =====================================
        // FILE
        // =====================================

        if (!file) {

            setError(
                "Please select an Excel .xlsx file first."
            );

            return;

        }


        try {

            setLoading(true);


            const result =
                await importBeneficiariesService(
                    file,
                    selectedOrganizationId
                );


            setMessage(
                result?.message ||
                "Beneficiary import completed successfully."
            );


            setFile(null);


        }

        catch (error) {

            const responseData =
                error?.response?.data;


            setError(

                responseData?.message ||

                responseData?.error ||

                error?.message ||

                "Beneficiary import failed."

            );

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================
    // DOWNLOAD TEMPLATE
    // =====================================

    const handleDownloadTemplate = async () => {

        setError("");
        setMessage("");


        if (!selectedOrganizationId) {

            setError(
                "Please select an organization before downloading the beneficiary template."
            );

            return;

        }


        try {

            setLoading(true);


            const blob =
                await downloadBeneficiaryTemplateService(
                    selectedOrganizationId
                );


            const fileBlob =
                blob instanceof Blob
                    ? blob
                    : new Blob(
                        [blob],
                        {
                            type:
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        }
                    );


            const url =
                window.URL.createObjectURL(
                    fileBlob
                );


            const link =
                document.createElement("a");


            link.href = url;

            link.setAttribute(
                "download",
                "beneficiary_template.xlsx"
            );


            document.body.appendChild(
                link
            );


            link.click();


            document.body.removeChild(
                link
            );


            window.URL.revokeObjectURL(
                url
            );

        }

        catch (error) {

            setError(

                error?.response?.data?.message ||

                error?.message ||

                "Beneficiary template download failed."

            );

        }

        finally {

            setLoading(false);

        }

    };


    // =====================================
    // BACK TO LIST
    // =====================================

    const handleBack = () => {

        navigate(
            "/beneficiaries"
        );

    };


    // =====================================
    // RENDER
    // =====================================

    return (
        <PageCard>

            <Stack spacing={3}>


                {/* =====================================
                    HEADER
                ===================================== */}

                <Stack sx={{ alignItems: "center" }}
                    direction="row"
                    spacing={2}
                >

                    <Button
                        variant="text"
                        startIcon={
                            <ArrowBack />
                        }
                        onClick={
                            handleBack
                        }
                        disabled={loading}
                    >
                        Back
                    </Button>


                    <Typography
                        variant="h6"
                        sx={{
                            fontWeight: 600
                        }}
                    >
                        Import Beneficiaries
                    </Typography>

                </Stack>


                {/* =====================================
                    ORGANIZATION WARNING
                ===================================== */}

                {!selectedOrganizationId && (

                    <Alert severity="warning">

                        Please select an organization before
                        downloading the template or importing
                        beneficiaries.

                    </Alert>

                )}


                {/* =====================================
                    DESCRIPTION
                ===================================== */}

                <Typography
                    variant="body2"
                    sx={{
                        color: "text.secondary"
                    }}
                >
                    Download the Excel template, fill in the
                    beneficiary information, then upload the
                    completed .xlsx file.
                </Typography>


                {/* =====================================
                    IMPORT RULES
                ===================================== */}

                <Alert severity="info">

                    <Typography
                        variant="body2"
                    >
                        <strong>Important:</strong>{" "}
                        Age is calculated automatically from
                        Date of Birth. Do not enter or modify
                        age manually.
                    </Typography>

                </Alert>


                {/* =====================================
                    DOWNLOAD TEMPLATE
                ===================================== */}

                <Button
                    variant="outlined"
                    startIcon={
                        <Download />
                    }
                    onClick={
                        handleDownloadTemplate
                    }
                    disabled={
                        loading ||
                        !selectedOrganizationId
                    }
                >
                    Download Excel Template
                </Button>


                {/* =====================================
                    SELECT FILE
                ===================================== */}

                <Button
                    component="label"
                    variant="outlined"
                    startIcon={
                        <UploadFile />
                    }
                    disabled={
                        loading ||
                        !selectedOrganizationId
                    }
                >

                    Select Excel File

                    <input
                        hidden
                        type="file"
                        accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        onChange={
                            handleFileChange
                        }
                    />

                </Button>


                {/* =====================================
                    SELECTED FILE
                ===================================== */}

                {file && (

                    <Typography
                        variant="body2"
                    >

                        Selected:{" "}

                        <strong>
                            {file.name}
                        </strong>

                    </Typography>

                )}


                {/* =====================================
                    LOADING
                ===================================== */}

                {loading && (

                    <LoadingState
                        message={
                            "Processing beneficiary import..."
                        }
                    />

                )}


                {/* =====================================
                    IMPORT BUTTON
                ===================================== */}

                <Button
                    variant="contained"
                    disabled={
                        loading ||
                        !file ||
                        !selectedOrganizationId
                    }
                    onClick={
                        handleImport
                    }
                >

                    {loading
                        ? "Importing..."
                        : "Upload & Import"
                    }

                </Button>


                {/* =====================================
                    SUCCESS
                ===================================== */}

                {message && (

                    <Alert severity="success">

                        {message}

                    </Alert>

                )}


                {/* =====================================
                    ERROR
                ===================================== */}

                {error && (

                    <Alert severity="error">

                        {error}

                    </Alert>

                )}

            </Stack>

        </PageCard>
    );

};


export default BeneficiaryImport;