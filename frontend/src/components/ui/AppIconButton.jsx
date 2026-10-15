import {
    IconButton,
    Tooltip
} from "@mui/material";


const AppIconButton = ({
    icon,

    tooltip,

    size = "small",

    color = "default",

    disabled = false,

    onClick,

    ...props
}) => {

    const button = (
        <IconButton
            size={size}
            color={color}
            disabled={disabled}
            onClick={onClick}
            {...props}
        >
            {icon}
        </IconButton>
    );


    if (!tooltip) {
        return button;
    }


    return (
        <Tooltip title={tooltip}>
            <span>
                {button}
            </span>
        </Tooltip>
    );
};


export default AppIconButton;