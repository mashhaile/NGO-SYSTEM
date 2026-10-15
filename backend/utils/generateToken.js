const jwt = require("jsonwebtoken");

function generateToken(user) {
    return jwt.sign(
        {
            userId: user._id,
            organizationId: user.organization,
            role: user.role,
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "7d",
        }
    );
}

module.exports = generateToken;