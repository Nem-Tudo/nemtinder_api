const jwt = require('jsonwebtoken');
module.exports = ({ requiredFlags, blockedFlags, select, optional }, userSchema) => async (req, res, next) => {
    const authorization = req.headers?.authorization;

    if (!authorization) {
        if(optional) return next()
        return res.status(401).json({
            message: "401: Token not provided"
        });

    }
    if (typeof authorization !== 'string') return res.status(401).send({ message: "401: Unauthorized" });

    const parts = authorization.split(".")

    if (parts.length != 3) return res.status(401).send({ message: "401: Unauthorized" });

    if (authorization.length < 79) return res.status(401).send({ message: "401: Unauthorized" });

    try {
        const decoded = jwt.verify(authorization, process.env.JWTKEY);

        const userid = decoded?.data?.id;
        if (!userid) return res.status(401).send({ message: "401: Unauthorized" });

        const user = await userSchema.findOne({
            id: userid
        }).select(select);

        if (!user) return res.status(401).send({ message: "401: Unauthorized" });

        if (!user.flags.includes("ADMIN")) {
            if (requiredFlags && requiredFlags.some(flag => !user.flags.includes(flag))) return res.status(403).send({ message: `403: This route cannot be accessed because you don't have all the required flags.` });

            if (blockedFlags && blockedFlags.some(flag => user.flags.includes(flag))) return res.status(403).send({ message: `403: This route cannot be accessed because you have a blocked flag.` });
        }

        req.user = user;

        return next();

    } catch (error) {
        return res.status(401).send({ message: "401: Unauthorized" });
    }

}