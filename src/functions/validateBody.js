
const { validationResult } = require('express-validator');

module.exports = () => (req, res, next) => {
    const bodyErrors = validationResult(req).formatWith(({ type, value, msg, path, location, nestedErrors }) => {
        return {
            message: msg,
            value: value,
            location: location,
            path: path
        }
    });

    if (bodyErrors.isEmpty()) return next();

    res.status(400).json({
        message: `400: Invalid Form Body`,
        errors: bodyErrors.array()
    })

}