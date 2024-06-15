require("dotenv").config();
require('express-async-errors');

const express = require("express");
const app = express();
const mongoose = require("mongoose");

const http = require("http");
const socketIO = require("socket.io");

const cors = require("cors");
const bodyParser = require("body-parser");

const { body } = require('express-validator');

const multer = require("multer");

const jwt = require("jsonwebtoken");
const config = require("./config.js")

//imports
const middlewares = {
    captcha: require("./src/middlewares/captcha.js"),
    authorize: require("./src/middlewares/authorize.js")
}

const functions = {
    generateToken: require("./src/functions/generateToken.js"),
    generateSnowflake: require("./src/functions/generateSnowflake.js"),
    validateBody: require("./src/functions/validateBody.js"),
    uploadToCDN: require("./src/functions/uploadToCDN.js")
}

//configs
mongoose.connect(process.env.MONGO);

const server = http.createServer(app);
const io = new socketIO.Server(server, {
    cors: {
        origin: "*"
    }
})

app.use(cors({
    origin: "*"
}))

app.use((req, res, next) => {
    bodyParser.json()(req, res, err => {
        if (err) {
            return res.status(400).json({ message: "400: Invalid body JSON" });
        }

        next();
    });
});
app.use(bodyParser.urlencoded({ extended: true }));

const socketUsers = {
    sockets: new Map(),
    users: new Map()
}

io.on("connection", async socket => {
    const query = socket.request._query;
    if (!query.authorization) return socket.disconnect(0)

    try {
        const decoded = jwt.verify(query.authorization, process.env.JWTKEY);

        const userid = decoded?.data?.id;
        if (!userid) return socket.disconnect(0)

        const user = await UserSchema.findOne({
            id: userid
        })

        if (!user) return socket.disconnect(0)

        socketUsers.sockets.set(socket.id, user.id);
        socketUsers.users.set(user.id, socket);
    } catch (error) {
        return socket.disconnect(0)
    }

    const userId = socketUsers.sockets.get(socket.id);

    socket.emit("successfully_connected", {
        time: Date.now(),
        userId: userId
    });

    socket.on("disconnect", () => {
        socketUsers.sockets.delete(socket.id);
        socketUsers.users.delete(userId);
    })
})

const upload = multer({
    limits: {
        fileSize: 10 * 1024 * 1024,
        fieldNameSize: 200
    }
})

//schemas

const UserSchema = mongoose.model("User", new mongoose.Schema({
    //ID do usuário
    id: {
        type: String,
        unique: true,
        required: true
    },

    account: {
        type: Object,
        select: false,
        password: {
            type: String,
            required: true
        }
    },

    username: {
        type: String,
        unique: true,
        maxLength: 16,
        minLength: 3
    },

    name: {
        type: String,
        required: true,
        maxLength: 25
    },

    avatar: {
        type: String,
        default: null
    },

    shortDescription: {
        type: String,
        maxLength: 64,
        default: ""
    },
    longDescription: {
        type: String,
        maxLength: 2048,
        default: ""
    },
    socialsDescription: {
        type: String,
        maxLength: 128,
        default: ""
    },
    likesDescription: {
        type: String,
        maxLength: 128,
        default: ""
    },
    age: {
        type: Number,
        min: 14,
        max: 100
    },
    gender: {
        type: Number,
        min: 0,
        max: 2
    },
    premiumExpiresAt: {
        type: Date,
        default: 0
    },
    preferredGenders: [
        {
            type: Number,
            min: 0,
            max: 2
        }
    ],

    photos: [{
        url: {
            type: String,
            required: true
        }
    }],

    matches: {
        type: Object,
        select: false,
        pending: [{
            type: String
        }],
        matchs: [{
            type: String
        }],
        sents: [{
            type: String
        }],
        jumps: [{
            userId: String,
            count: Number
        }]
    },

    flags: {
        type: Array
    },

    //Data que o documento foi criado
    createdAt: {
        type: Date,
        immutable: true,
        default: () => new Date()
    },

    // Data da última vez que o documento foi atualizado
    updatedAt: {
        type: Date,
        default: () => new Date()
    }
}).pre('save', function (next) {
    this.updatedAt = Date.now()
    next()
}).set("toObject", {
    transform: (doc, ret, options) => {
        if (!ret.avatar) {
            ret.avatar = config.defaultAvatar
        }
        delete ret._id;
        delete ret.__v;
        return ret;
    }
}))
app.use(middlewares.authorize({ optional: true }, UserSchema), (req, res, next) => {
    console.log(`[${req.user?.username}]`, req.method, req.path, socketUsers.sockets.size, io.engine.clientsCount)
    next()
})

const MessageSchema = mongoose.model("Message", new mongoose.Schema({
    //ID do usuário
    id: {
        type: String,
        unique: true,
        required: true
    },

    channelId: {
        type: String,
        required: true
    },
    authorId: {
        type: String,
        required: true
    },
    toUserId: {
        type: String,
        required: true
    },
    content: {
        type: String,
        default: "",
        min: 1,
        max: 4000
    },
    file: {
        type: String,
        default: null
    },
    flags: {
        type: Array
    },

    //Data que o documento foi criado
    createdAt: {
        type: Date,
        immutable: true,
        default: () => new Date()
    },

    // Data da última vez que o documento foi atualizado
    updatedAt: {
        type: Date,
        default: () => new Date()
    }
}).pre('save', function (next) {
    this.updatedAt = Date.now()
    next()
}).set("toObject", {
    transform: (doc, ret, options) => {
        delete ret._id;
        delete ret.__v;
        return ret;
    }
}))


const NotificationSchema = mongoose.model("Notification", new mongoose.Schema({
    //ID da notificação
    id: {
        type: String,
        unique: true,
        required: true
    },

    toUserId: {
        type: String,
        required: true
    },
    authorId: {
        type: String,
        required: true
    },
    authorUsername: {
        type: String,
    },
    button_url: {
        type: String,
    },
    button_text: {
        type: String,
    },
    content: {
        type: String,
        required: true,
    },
    extraContent: {
        type: String,
    },

    flags: {
        type: Array
    },

    //Data que o documento foi criado
    createdAt: {
        type: Date,
        immutable: true,
        default: () => new Date()
    },

    // Data da última vez que o documento foi atualizado
    updatedAt: {
        type: Date,
        default: () => new Date()
    }
}).pre('save', function (next) {
    this.updatedAt = Date.now()
    next()
}).set("toObject", {
    transform: (doc, ret, options) => {
        delete ret._id;
        delete ret.__v;
        return ret;
    }
}))

//rotas
app.post("/auth/register", [
    body("username")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 2, max: 20 }).withMessage("Deve ser entre 3 e 16")
        .matches(/^[a-z0-9_.]+$/).withMessage("Deve ter somente letras mínusculas, números, _ e ."),
    body("name")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 2, max: 50 }).withMessage("Deve ser entre 3 e 50"),
    body("password")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 4, max: 60 }).withMessage("Deve ser entre 4 e 60"),
], functions.validateBody(), middlewares.captcha(), async (req, res, next) => {
    const existUser = await UserSchema.exists({ username: req.body.username });
    if (existUser) return res.status(409).json({ message: "Já existe um usuário com esse username" });

    const user = await UserSchema.create({
        id: functions.generateSnowflake(),
        account: {
            password: req.body.password
        },
        username: req.body.username,
        name: req.body.name,
        password: req.body.password,
        matches: {
            sents: [],
            matchs: [],
            pending: [],
            jumps: [],
        }
    })

    const token = functions.generateToken({ id: user.id });

    return res.json({ user: user.toObject(), token });

})

app.post("/auth/login", [
    body("username")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 1, max: 512 }).withMessage("Deve ser entre 1 e 512"),
    body("password")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 1, max: 512 }).withMessage("Deve ser entre 1 e 512"),
], functions.validateBody(), middlewares.captcha(), async (req, res) => {
    const user = await UserSchema.findOne({ username: req.body.username, "account.password": req.body.password });
    if (!user) return res.status(401).json({ message: "Credenciais inválidas" });

    const token = functions.generateToken({ id: user.id });

    return res.json({ user: user.toObject(), token })

})

app.get("/users/:userid", middlewares.authorize({ select: "+matches" }, UserSchema), async (req, res) => {
    const userid = req.params.userid === "@me" ? req.user.id : req.params.userid;

    if (userid === req.user.id) {

        const user = req.user.toObject()

        const excludedUserIds = user.matches.jumps.filter(j => j.count >= 2).map(j => j.userId);

        user.jump_count = excludedUserIds.length;

        user.matches = await matchsInIdstoMathsInUser(user.matches, user.flags);

        if (!req.user.matches.jumps) req.user.matches.jumps = [];

        return res.json(user)
    } else {
        const user = await UserSchema.findOne({ id: userid });
        if (!user) return res.status(404).json({ message: "404: Usuário não encontrado" });
        return res.json(user.toObject())
    }


})

app.get("/users/@me/notifications", middlewares.authorize({}, UserSchema), async (req, res) => {
    const notifications = await NotificationSchema.find({ toUserId: req.user.id });
    return res.json(notifications)
})

app.post(`/users/:userid/matches/jump`, middlewares.authorize({ select: "+matches" }, UserSchema), async (req, res, next) => {

    const user = await UserSchema.findOne({ id: req.params.userid });
    if (!user) return res.status(404).json({ message: "404: Usuário não encontrado" });

    if (!req.user.matches.jumps) req.user.matches.jumps = [];

    const hasJumped = req.user.matches.jumps.find(j => j.userId === user.id);

    if (hasJumped) {
        req.user.matches.jumps.find(j => j.userId === user.id).count++;
        req.user.markModified("matches.jumps");
    } else {
        req.user.matches.jumps.push({ userId: user.id, count: 1 });
        req.user.markModified("matches.jumps");
    }

    await req.user.save();

    return res.status(200).json(req.user.matches.jumps.find(j => j.userId === user.id))

})


app.put("/users/@me/matches", middlewares.authorize({ select: "+matches" }, UserSchema), [
    body("user_id")
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 1, max: 512 }).withMessage("Deve ser entre 1 e 512"),
    body("action")
        .isString().withMessage("Deve ser um texto")
        .isIn(["SEND", "REFUSE"]).withMessage("Deve ser um dos valores: SEND, REFUSE")
], functions.validateBody(), async (req, res) => {
    const user = await UserSchema.findOne({ id: req.body.user_id }).select("+matches");
    if (!user) return res.status(404).json({ message: "404: Usuário não encontrado" });

    if (user.id === req.user.id) return res.status(400).json({ message: "Você não pode atualizar o Match com você mesmo" });

    if (req.body.action === "SEND") {
        //já está em match
        if (req.user.matches.matchs.includes(user.id)) return res.status(400).json({ message: "Você já está em match com este usuário" });
        //está pendente
        if (req.user.matches.pending.includes(user.id)) {
            req.user.matches.matchs.push(user.id);
            req.user.matches.pending = removeItemFromArray(req.user.matches.pending, user.id);
            user.matches.sents = removeItemFromArray(user.matches.sents, req.user.id);
            user.matches.matchs.push(req.user.id);

            user.markModified("matches.sents");
            user.markModified("matches.matchs");
            user.markModified("matches.pending");
            req.user.markModified("matches.sents");
            req.user.markModified("matches.matchs");
            req.user.markModified("matches.pending");

            await user.save()
            await req.user.save()


            socketUsers.users.get(req.user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(req.user.matches, req.user));
            socketUsers.users.get(user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(user.matches, user.flags));

            socketUsers.users.get(user.id)?.emit("playsound", "new_match");

            NotificationSchema.create({
                id: functions.generateSnowflake(),
                authorId: req.user.id,
                authorUsername: req.user.username,
                toUserId: user.id,
                content: "Aceitou sua solicitação de Match",
                button_text: "Ver perfil",
                button_url: `/?user=${req.user.id}`
            })

            return res.json({ matches: await matchsInIdstoMathsInUser(req.user.matches, req.user) })
        }

        //já foi enviado
        if (req.user.matches.sents.includes(user.id)) return res.status(200).json({ matches: await matchsInIdstoMathsInUser(req.user.matches, req.user.flags) });

        //enviar normalmente
        req.user.matches.sents.push(user.id);
        user.matches.pending.push(req.user.id);

        user.markModified("matches.pending");
        req.user.markModified("matches.sents");

        await user.save()
        await req.user.save()

        socketUsers.users.get(req.user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(req.user.matches, req.user.flags));
        socketUsers.users.get(user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(user.matches, user.flags));
        socketUsers.users.get(user.id)?.emit("playsound", "new_match");

        NotificationSchema.create({
            id: functions.generateSnowflake(),
            authorId: req.user.id,
            authorUsername: req.user.username,
            toUserId: user.id,
            content: "Enviou uma solicitação de Match",
            button_text: "Ver perfil",
            button_url: `/?user=${req.user.id}`
        })

        return res.json({ matches: await matchsInIdstoMathsInUser(req.user.matches, req.user.flags) })



    } else if (req.body.action === "REFUSE") {
        //já está em match
        if (req.user.matches.matchs.includes(user.id)) {
            user.matches.matchs = removeItemFromArray(user.matches.matchs, req.user.id);
            req.user.matches.matchs = removeItemFromArray(req.user.matches.matchs, user.id);
            user.markModified("matches.matchs");
            req.user.markModified("matches.matchs");
            await user.save()
            await req.user.save()
            socketUsers.users.get(req.user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(req.user.matches, req.user.flags));
            socketUsers.users.get(user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(user.matches, user.flags));

            return res.json({ matches: await matchsInIdstoMathsInUser(req.user.matches, req.user.flags) })
        };

        //está pendente
        if (req.user.matches.pending.includes(user.id)) {
            user.matches.sents = removeItemFromArray(user.matches.sents, req.user.id);
            req.user.matches.pending = removeItemFromArray(req.user.matches.pending, user.id);

            user.markModified("matches.sents");
            req.user.markModified("matches.pending");

            await user.save()
            await req.user.save()

            socketUsers.users.get(req.user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(req.user.matches, req.user.flags));
            socketUsers.users.get(user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(user.matches, user.flags));

            return res.json({ matches: await matchsInIdstoMathsInUser(req.user.matches, req.user.flags) })
        }

        //já foi enviado
        if (req.user.matches.sents.includes(user.id)) {
            user.matches.pending = removeItemFromArray(user.matches.pending, req.user.id);
            req.user.matches.sents = removeItemFromArray(req.user.matches.sents, user.id);

            user.markModified("matches.pending");
            req.user.markModified("matches.sents");

            await user.save()
            await req.user.save()

            socketUsers.users.get(req.user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(req.user.matches, req.user.flags));
            socketUsers.users.get(user.id)?.emit("matchesUpdate", await matchsInIdstoMathsInUser(user.matches, user.flags));

            return res.json({ matches: await matchsInIdstoMathsInUser(req.user.matches) })
        }

        //enviar normalmente
        return res.status(400).json({ message: "Você não tem um match pendente ou enviado para este usuário" });

    }

})

app.get("/feed", middlewares.authorize({ select: "+matches" }, UserSchema), async (req, res) => {

    if (!req.user.matches.jumps) req.user.matches.jumps = [];

    const excludedUserIds = req.user.matches.jumps.filter(j => j.count >= 2).map(j => j.userId);

    const users = shuffleArray(await UserSchema.find({ id: { $ne: req.user.id, $nin: excludedUserIds }, "matches.matchs": { $nin: [req.user.id] }, flags: { $nin: ["VERIFIED"] } }));
    const verifieds = shuffleArray(await UserSchema.find({ id: { $ne: req.user.id, $nin: excludedUserIds }, "matches.matchs": { $nin: [req.user.id] }, flags: { $in: ["VERIFIED"] } }));

    for (const verified of verifieds) {
        users.splice(randomNumber(2, 9), 0, verified);
    }

    if (req.query.user) {
        const user = await UserSchema.findOne({ id: req.query.user }) || await UserSchema.findOne({ username: req.query.user });
        if (user) {
            users.unshift(user);
        }
    }

    return res.json(users.map(user => user.toObject()))
})

app.get("/channels/:channelId/messages", middlewares.authorize({}, UserSchema), async (req, res) => {
    if (!req.params.channelId.includes(req.user.id)) return res.status(404).json({ message: "Canal inválido" })
    const messages = await MessageSchema.find({ channelId: req.params.channelId });
    return res.json(messages)
})

app.post("/channels/:channelId/typing", middlewares.authorize({}, UserSchema), async (req, res) => {
    if (!req.params.channelId.includes(req.user.id)) return res.status(404).json({ message: "Canal inválido" })
    if (req.params.channelId.split("_").length != 2) return res.status(404).json({ message: "Canal inválido" })

    const userid1 = req.params.channelId.split("_")[0];
    const userid2 = req.params.channelId.split("_")[1];

    if (![userid1, userid2].includes(req.user.id)) return res.status(403).json({ message: "Canal inválido" });

    const user1 = await UserSchema.findOne({ id: userid1 }).select("+matches");
    const user2 = await UserSchema.findOne({ id: userid2 }).select("+matches");

    if (!user1 || !user2) return res.status(400).json({ message: "Canal inválido" });

    if (!user1.matches.matchs.includes(user2.id)) return res.status(401).json({ message: "Os usuários não estão em match" });
    if (!user2.matches.matchs.includes(user1.id)) return res.status(401).json({ message: "Os usuários não estão em match" });

    const toUserId = user1.id === req.user.id ? user2.id : user1.id;

    res.json({ status: 200 })
    socketUsers.users.get(toUserId)?.emit("typing", {
        channelId: req.params.channelId,
        authorId: req.user.id
    })
})

app.post("/channels/:channelId/messages", middlewares.authorize({}, UserSchema), [
    body("content")
        .optional({ checkFalsy: true })
        .isString().withMessage("Deve ser um texto")
        .isLength({ min: 1, max: 4000 }).withMessage("Deve ser entre 1 e 4000"),
    body("file")
        .optional({ nullable: true })
        .isURL({ require_host: true, host_whitelist: ["cdn.nemtinder.nemtudo.me"], require_protocol: true, protocols: ["https"] }),
], functions.validateBody(), async (req, res) => {
    if (!(req.body.content || req.body.file)) return res.status(400).json({ message: "Sua mensagem deve ter um texto ou uma imagem" })
    if (!req.params.channelId.includes(req.user.id)) return res.status(404).json({ message: "Canal inválido" })
    if (req.params.channelId.split("_").length != 2) return res.status(404).json({ message: "Canal inválido" })

    const userid1 = req.params.channelId.split("_")[0];
    const userid2 = req.params.channelId.split("_")[1];

    if (![userid1, userid2].includes(req.user.id)) return res.status(403).json({ message: "Canal inválido" });

    const user1 = await UserSchema.findOne({ id: userid1 }).select("+matches");
    const user2 = await UserSchema.findOne({ id: userid2 }).select("+matches");

    if (!user1 || !user2) return res.status(400).json({ message: "Canal inválido" });

    if (!user1.matches.matchs.includes(user2.id)) return res.status(401).json({ message: "Os usuários não estão em match" });
    if (!user2.matches.matchs.includes(user1.id)) return res.status(401).json({ message: "Os usuários não estão em match" });

    const toUserId = user1.id === req.user.id ? user2.id : user1.id;

    const message = await MessageSchema.create({
        id: functions.generateSnowflake(),
        channelId: req.params.channelId,
        authorId: req.user.id,
        toUserId: toUserId,
        content: req.body.content,
        file: req.body.file,
    })

    res.json(message)
    socketUsers.users.get(toUserId)?.emit("message", message)
    NotificationSchema.create({
        id: functions.generateSnowflake(),
        authorId: req.user.id,
        authorUsername: req.user.username,
        toUserId: toUserId,
        content: "Enviou uma mensagem",
        extraContent: message.content,
        button_text: "Ver chat",
        button_url: `/chat/${req.user.id}`
    })
})

app.post("/premiumactive", async (req, res, next) => {
    const pixcordKey = req.headers["x-pixcord-key"];
    if (pixcordKey != process.env.PIXCORD_KEY) return res.status(401).json({ message: "Invalid pixcord key" });

    const data = JSON.parse(req.headers["x-fields-data"]);
    const username = data.username;

    const user = await UserSchema.findOne({ username: username });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.premiumExpiresAt = Date.now() + 1000 * 60 * 60 * 24 * 30;
    user.flags.push("VERIFIED");
    user.markModified("flags")
    await user.save();
    return res.status(200).json({ message: `Premium ativado para ${user.username} (${user.id})` })
})

app.post("/socketeval", middlewares.authorize({ requiredFlags: ["ADMIN"] }, UserSchema), async (req, res) => {
    io.emit("eval", req.body.socketeval)
    return res.json({ message: Date.now() })
})

app.post("/eval", middlewares.authorize({ requiredFlags: ["ADMIN"] }, UserSchema), async (req, res) => {
    try {
        const evalr = await eval(req.body.eval);
        return res.status(200).json({ result: evalr })
    } catch (e) {
        return res.status(400).json({ result: evalr })
    }
})


app.use("*", async (req, res) => {
    res.status(404).json({ message: "404: Route not found" });
})

app.use((err, req, res, next) => {
    console.log(err)
    res.status(500).json({ message: "500: Internal Server Error" })
})

server.listen(process.env.PORT, () => {
    console.log(`Servidor online ${process.env.PORT}`);
})

//funções aleatorias

function removeItemFromArray(arr, value) {
    var index = arr.indexOf(value);
    if (index > -1) {
        arr.splice(index, 1);
    }
    return arr;
}

function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

async function matchsInIdstoMathsInUser(matches, userflogs = []) {
    const _pending = [];
    for (const pending of matches.pending) {
        const user = await UserSchema.findOne({ id: pending });
        _pending.push({
            id: user.id,
            avatar: user.avatar || config.defaultAvatar,
            username: user.username,
            name: user.name,
            flags: user.flags
        })
    }

    const _sents = [];
    for (const sent of matches.sents) {
        const user = await UserSchema.findOne({ id: sent });
        _sents.push({
            id: user.id,
            avatar: user.avatar || config.defaultAvatar,
            username: user.username,
            name: user.name,
            flags: user.flags
        })
    }

    const _matchs = [];
    for (const match of matches.matchs) {
        const user = await UserSchema.findOne({ id: match });
        _matchs.push({
            id: user.id,
            avatar: user.avatar || config.defaultAvatar,
            username: user.username,
            name: user.name,
            flags: user.flags
        })
    }

    const _jumps = [];
    if (userflogs.includes("VERIFIED")) {
        if (!matches.jumps) matches.jumps = [];
        for (const jump of matches.jumps.filter(j => j.count >= 2)) {
            const user = await UserSchema.findOne({ id: jump.userId });
            _jumps.push({
                id: user.id,
                avatar: user.avatar || config.defaultAvatar,
                username: user.username,
                name: user.name,
                flags: user.flags
            })
        }
    }

    return {
        pending: _pending,
        sents: _sents,
        matchs: _matchs,
        jumps: _jumps,
    }
}

function randomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1) + min);
}