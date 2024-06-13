const jwt = require("jsonwebtoken");

module.exports = (data) => {
    return jwt.sign({ createdAt: Date.now(), data }, process.env.JWTKEY);
}