// --- keyauth-system/index.js ---
const express = require("express");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: "yourSecretKeyHere",
    resave: false,
    saveUninitialized: false
}));
app.set("view engine", "ejs");
app.use(express.static("public"));

const dbFile = "./db.json";
if (!fs.existsSync(dbFile)) fs.writeFileSync(dbFile, JSON.stringify({ keys: [], logs: [] }, null, 2));

function loadDB() {
    return JSON.parse(fs.readFileSync(dbFile));
}

function saveDB(data) {
    fs.writeFileSync(dbFile, JSON.stringify(data, null, 2));
}

// --- Middleware ---
function authMiddleware(req, res, next) {
    if (req.session.loggedIn) return next();
    res.redirect("/admin/login");
}

// --- Routes ---

// Home (Optional)
app.get("/", (req, res) => res.send("<h1>KeyAuth System</h1>"));

// Admin login
app.get("/admin/login", (req, res) => res.render("login"));
app.post("/admin/login", async (req, res) => {
    const { username, password } = req.body;
    if (username === "admin" && await bcrypt.compare(password, "$2b$10$NjZ0WhZ9yK1KqJkh1r/7aOaQe8.RTjcsHDuWv4KDRx6Ya7M0nMNU6")) {
        req.session.loggedIn = true;
        res.redirect("/admin");
    } else {
        res.send("Invalid login");
    }
});

// Admin dashboard
app.get("/admin", authMiddleware, (req, res) => {
    const db = loadDB();
    res.render("admin", { keys: db.keys });
});

app.post("/admin/create-key", authMiddleware, (req, res) => {
    const { key, expiresIn } = req.body;
    const db = loadDB();
    db.keys.push({ key, expiresIn: parseInt(expiresIn), redeemedAt: null, hwid: null });
    saveDB(db);
    res.redirect("/admin");
});

app.post("/admin/delete-key", authMiddleware, (req, res) => {
    const { key } = req.body;
    let db = loadDB();
    db.keys = db.keys.filter(k => k.key !== key);
    saveDB(db);
    res.redirect("/admin");
});

// API to redeem key
app.post("/api/redeem", (req, res) => {
    const { key, hwid } = req.body;
    let db = loadDB();
    const target = db.keys.find(k => k.key === key);
    if (!target) return res.status(404).json({ success: false, message: "Key not found" });

    if (!target.redeemedAt) {
        target.hwid = hwid;
        target.redeemedAt = Date.now();
        saveDB(db);
        return res.json({ success: true, message: "Key redeemed" });
    }

    if (target.hwid !== hwid) return res.status(403).json({ success: false, message: "Invalid HWID" });
    if (Date.now() > target.redeemedAt + target.expiresIn * 1000) return res.status(403).json({ success: false, message: "Key expired" });

    return res.json({ success: true, message: "Access granted" });
});

app.listen(PORT, () => console.log(`KeyAuth running on port ${PORT}`));
