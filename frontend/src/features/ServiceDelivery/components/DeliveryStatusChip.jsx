import {
    useRef,
    useState
} from "react";


import {
    Button,
    Stack,
    Typography,
    Paper,
    LinearProgress,
    Alert
} from "@mui/material";


import UploadFileIcon
    from "@mui/icons-material/UploadFile";


import DownloadIcon
    from "@mui/icons-material/Download";


import {
    importBeneficiariesService,
    downloadBeneficiaryTemplateService
} from "../services/beneficiaryImportService";


// =====================================================
// BENEFICIARY IMPORT
// =====================================================

const BeneficiaryImport = () => {

    const fileInputRef =
        useRef(null);


    const [file, setFile] =
        useState(null);


    const [loading, setLoading] =
        useState(false);


    const [downloading, setDownloading] =
        useState(false);


    const [message, setMessage] =
        useState("");


    const [error, setError] =
        useState("");


    // =================================================
    // SELECT FILE
    // =================================================

    const handleFileChange = (
        e
    ) => {

        const selectedFile =
            e.target.files?.[0] ||
            null;


        setFile(
            selectedFile
        );


        setMessage(
            ""
        );


        setError(
            ""
        );

    };


    // =================================================
    // IMPORT
    // =================================================

    const handleImport = async () => {

        if (!file) {

            setError(
                "Please select an Excel file first."
            );

            return;

        }


        try {

            setLoading(
                true
            );


            setMessage(
                ""
            );


            setError(
                ""
            );


            const result =
                await importBeneficiariesService(
                    file
                );


            setMessage(
                result?.message ||
                "Import completed successfully."
            );


            setFile(
                null
            );


            if (
                fileInputRef.current
            ) {

                fileInputRef.current.value =
                    "";

            }

        }
        catch (
            error
        ) {

            setError(
                error?.response?.data?.message ||
                error?.message ||
                "Import failed."
            );

        }
        finally {

            setLoading(
                false
            );

        }

    };


    // =================================================
    // DOWNLOAD TEMPLATE
    // =================================================

    const handleDownloadTemplate = async () => {

        try {

            setDownloading(
                true
            );


            setMessage(
                ""
            );


            setError(
                ""
            );


            const blob =
                await downloadBeneficiaryTemplateService();


            const downloadBlob =
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
                    downloadBlob
                );


            const link =
                document.createElement(
                    "a"
                );


            link.href =
                url;


            link.setAttribute(
                "download",
                "beneficiary_template.xlsx"
            );


            document.body.appendChild(
                link
            );


            link.click();


            link.remove();


            window.URL.revokeObjectURL(
                url
            );

        }
        catch (
            error
        ) {

            setError(
                error?.response?.data?.message ||
                error?.message ||
                "Template download failed."
            );

        }
        finally {

            setDownloading(
                false
            );

        }

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Paper
            sx={{
                p: 3
            }}
        >

            <Stack
                spacing={3}
            >

                <Typography
                    variant="h6"
                >
                    Import Beneficiaries
                </Typography>


                {/* =====================================
                    TEMPLATE DOWNLOAD
                ===================================== */}

                <Button
                    variant="outlined"
                    startIcon={
                        <DownloadIcon />
                    }
                    onClick={
                        handleDownloadTemplate
                    }
                    disabled={
                        loading ||
                        downloading
                    }
                >

                    {
                        downloading
                            ? "Downloading..."
                            : "Download Excel Template"
                    }

                </Button>


                {/* =====================================
                    FILE SELECTION
                ===================================== */}

                <Button
                    component="label"
                    variant="outlined"
                    startIcon={
                        <UploadFileIcon />
                    }
                    disabled={
                        loading
                    }
                >

                    Select Excel File


                    <input
                        ref={
                            fileInputRef
                        }
                        hidden
                        type="file"
                        accept=".xlsx,.xls"
                        onChange={
                            handleFileChange
                        }
                    />

                </Button>


                {/* =====================================
                    SELECTED FILE
                ===================================== */}

                {
                    file && (

                        <Typography>

                            Selected:
                            {" "}
                            {file.name}

                        </Typography>

                    )
                }


                {/* =====================================
                    PROGRESS
                ===================================== */}

                {
                    loading && (

                        <LinearProgress />

                    )
                }


                {/* =====================================
                    IMPORT
                ===================================== */}

                <Button
                    variant="contained"
                    disabled={
                        loading ||
                        downloading ||
                        !file
                    }
                    onClick={
                        handleImport
                    }
                >

                    {
                        loading
                            ? "Importing..."
                            : "Upload & Import"
                    }

                </Button>


                {/* =====================================
                    SUCCESS MESSAGE
                ===================================== */}

                {
                    message && (

                        <Alert
                            severity="success"
                        >

                            {message}

                        </Alert>

                    )
                }


                {/* =====================================
                    ERROR MESSAGE
                ===================================== */}

                {
                    error && (

                        <Alert
                            severity="error"
                        >

                            {error}

                        </Alert>

                    )
                }

            </Stack>

        </Paper>

    );

};


export default BeneficiaryImport;