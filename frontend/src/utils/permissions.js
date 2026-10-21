// Can the signed-in user do this? Used to show or hide buttons;
// the API checks the permission again.
export const hasPermission = (user, permission) => {

    const permissions =
        Array.isArray(user?.permissions) ? user.permissions : [];

    return (
        user?.role === "super_admin" ||
        permissions.includes("*") ||
        permissions.includes(permission)
    );

};
