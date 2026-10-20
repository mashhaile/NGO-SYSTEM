import {
    IconButton,
    Menu,
    MenuItem,
    ListItemIcon,
    ListItemText,
    Tooltip
} from "@mui/material";

import {
    MoreVert
} from "@mui/icons-material";

import {
    useState
} from "react";


const ActionMenu = ({
    items = [],
    tooltip = "Actions",
    size = "small"
}) => {

    const [anchorEl, setAnchorEl] = useState(null);

    const open = Boolean(anchorEl);


    const handleOpen = (event) => {
        setAnchorEl(event.currentTarget);
    };


    const handleClose = () => {
        setAnchorEl(null);
    };


    const handleItemClick = (item) => {

        handleClose();

        if (!item.disabled) {
            item.onClick?.();
        }

    };


    return (
        <>
            <Tooltip title={tooltip}>
                <IconButton
                    size={size}
                    onClick={handleOpen}
                    aria-label={tooltip}
                    aria-haspopup="menu"
                    aria-expanded={open ? "true" : undefined}
                >
                    <MoreVert fontSize="small" />
                </IconButton>
            </Tooltip>

            <Menu
                anchorEl={anchorEl}
                open={open}
                onClose={handleClose}
                anchorOrigin={{
                    vertical: "bottom",
                    horizontal: "right"
                }}
                transformOrigin={{
                    vertical: "top",
                    horizontal: "right"
                }}
                slotProps={{
                    paper: {
                        elevation: 0,
                        sx: {
                            mt: 0.75,
                            minWidth: 180,
                            borderRadius: 2,
                            border: "1px solid",
                            borderColor: "divider",
                            boxShadow:
                                "0 12px 35px rgba(15,23,42,0.12)",
                            overflow: "hidden"
                        }
                    }
                }}
            >

                {items.map((item, index) => (

                    <MenuItem
                        key={
                            item.key ??
                            item.label ??
                            index
                        }
                        disabled={item.disabled}
                        onClick={() =>
                            handleItemClick(item)
                        }
                        sx={{
                            minHeight: 42,
                            px: 1.5,
                            gap: 1,

                            color:
                                item.color
                                || "text.primary",

                            "&:hover": {
                                backgroundColor:
                                    "action.hover"
                            }
                        }}
                    >

                        {item.icon && (
                            <ListItemIcon
                                sx={{
                                    minWidth: 32,
                                    color:
                                        item.color
                                        || "text.secondary"
                                }}
                            >
                                {item.icon}
                            </ListItemIcon>
                        )}

                        <ListItemText
                            primary={item.label}
                            slotProps={{
                                primary: {
                                    fontSize: "0.875rem",
                                    fontWeight: 500
                                }
                            }}
                        />

                    </MenuItem>

                ))}

            </Menu>
        </>
    );
};


export default ActionMenu;