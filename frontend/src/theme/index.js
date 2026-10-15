import { createTheme } from "@mui/material/styles";


const theme = createTheme({

    palette: {

        mode: "light",

        primary: {

            main: "#176B4D",

            light: "#E6F2ED",

            dark: "#0F4A35",

            contrastText: "#FFFFFF"

        },

        secondary: {

            main: "#64748B",

            light: "#F1F5F9",

            dark: "#334155",

            contrastText: "#FFFFFF"

        },

        success: {

            main: "#15803D"

        },

        warning: {

            main: "#D97706"

        },

        error: {

            main: "#DC2626"

        },

        info: {

            main: "#2563EB"

        },

        background: {

            default: "#F6F8FB",

            paper: "#FFFFFF"

        },

        text: {

            primary: "#17211B",

            secondary: "#647067"

        },

        divider: "#E2E8E4"

    },


    shape: {

        borderRadius: 12

    },


    typography: {

        fontFamily:
            `"Inter", "Roboto", "Helvetica", "Arial", sans-serif`,

        h4: {

            fontWeight: 700

        },

        h5: {

            fontWeight: 700

        },

        h6: {

            fontWeight: 600

        },

        button: {

            textTransform: "none",

            fontWeight: 600

        }

    },


    components: {

        MuiButton: {

            styleOverrides: {

                root: {

                    borderRadius: 10,

                    paddingLeft: 18,

                    paddingRight: 18,

                    height: 42,

                    boxShadow: "none"

                },

                containedPrimary: {

                    "&:hover": {

                        backgroundColor: "#0F4A35",

                        boxShadow:
                            "0 4px 12px rgba(23, 107, 77, 0.20)"

                    }

                }

            }

        },


        MuiCard: {

            styleOverrides: {

                root: {

                    boxShadow:
                        "0 1px 3px rgba(15, 74, 53, 0.06)",

                    border:
                        "1px solid #E2E8E4"

                }

            }

        },


        MuiPaper: {

            styleOverrides: {

                root: {

                    boxShadow:
                        "0 1px 3px rgba(15, 74, 53, 0.05)"

                }

            }

        },


        MuiTextField: {

            defaultProps: {

                size: "small",

                fullWidth: true

            }

        },


        MuiOutlinedInput: {

            styleOverrides: {

                root: {

                    borderRadius: 10,

                    "&:hover .MuiOutlinedInput-notchedOutline": {

                        borderColor: "#176B4D"

                    },

                    "&.Mui-focused .MuiOutlinedInput-notchedOutline": {

                        borderColor: "#176B4D",

                        borderWidth: 2

                    }

                }

            }

        },


        MuiChip: {

            styleOverrides: {

                root: {

                    borderRadius: 8,

                    fontWeight: 600

                }

            }

        },


        MuiAppBar: {

            styleOverrides: {

                root: {

                    backgroundColor: "#FFFFFF",

                    color: "#17211B"

                }

            }

        },


        MuiListItemButton: {

            styleOverrides: {

                root: {

                    "&.active": {

                        backgroundColor: "#E6F2ED",

                        color: "#176B4D"

                    }

                }

            }

        }

    }

});


export default theme;
