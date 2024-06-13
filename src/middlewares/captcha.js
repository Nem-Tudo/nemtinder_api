const fetch = require("node-fetch");

module.exports = () => {
    return async (req, res, next) => {
        if (!req.headers["g-recaptcha-response"]) {
            return res.status(400).json({
                message: "400: Captcha inválido"
            })
        }

        const captcha = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.CAPTCHA_KEY}&response=${req.headers["g-recaptcha-response"]}`).then(r => r.json());

        if (captcha.success) return next();

        return res.status(400).json({
            message: "400: Captcha inválido"
        })
    }
}