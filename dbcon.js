
const mysql = require('mysql2');
const db = mysql.createPool({
    host: 'localhost',
    user: 'ffuser',
    password: 'ffuserApp2024',
    database: 'firstfriend',
});

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3405;
app.use(cors());
app.use(express.json());

const { pbkdf2Sync, createHash } = require('node:crypto');
const ITERATIONS = 10;
const KEYLEN = 64;
const DIGEST = 'sha256';

app.post("/api/auth", (req, res) => {
    const userName = req.body.userName;
    const authPass = req.body.pass;

    db.execute("SELECT * FROM user WHERE username = ?", [userName], (err, result) => {
        if (err || !Array.isArray(result) || !result.length) {
            console.error('Authentication error:', err ? err : result);
            res.status(406).send(false);
        } else {
            //console.log('Table result:', result[0]);
            const ITEM = result[0];
            const PROFILE = {
                sid: ITEM.student_id,
                firstname: ITEM.name_first,
                lastname: ITEM.name_last,
                username: ITEM.username,
                country: ITEM.country,
                major: ITEM.major,
                email: ITEM.email
            }
            const salt = ITEM.name_last + ITEM.student_id + ITEM.username + ITEM.name_first + '';
            const hashedPass = pbkdf2Sync(authPass, salt, ITERATIONS, KEYLEN, DIGEST).toString('hex');
            //console.log('Sent password:', authPass);
            //console.log('Hashed to:', hashedPass);
            //console.log('Against:', ITEM.password);
            const verify = ITEM.password === hashedPass;
            verify ? res.status(200).send(PROFILE) : res.status(401).send(false);
        }
    });
});

app.post("/api/create", (req, res) => {
    const data = req.body;
    const salt = data.lastName + data.id + data.userName + data.firstName;
    const password = pbkdf2Sync(data.password, salt, ITERATIONS, KEYLEN, DIGEST).toString('hex');
    const values = [data.id, data.firstName, data.lastName, data.userName, data.email, password, data.country, data.study];
    db.execute(`INSERT INTO firstfriend.user (student_id, name_first, name_last, username, email, password, country, major) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, values, (err, _result) => {
        if (err) {
            console.error('Create error:', err);
            res.status(406).send("Error creating user");
        } else {
            res.status(201).send("User Created");
        }
    });
});

app.post("/api/verify", (req, res) => {
    const data = req.body;
    const email = data.email;
    const username = data.username;
    const id = data.id;
    db.execute(`SELECT password FROM user WHERE username = ? AND student_id = ? AND email = ?`, [username, id, email], (err, result) => {
        if (err || !Array.isArray(result) || !result.length) {
            console.error('Verify error:', err ? err : result);
            res.status(403).send("Error in resetting password")
        } else {
            const key = createHash('sha256').update(Date.now().toString()).digest().toString('hex');
            db.execute(`UPDATE user SET password = ? WHERE username = ? AND student_id = ? AND email = ?`, [key, username, id, email], (uperr, _upres) => {
                if (uperr) {
                    res.status(503).send('Unknown error');
                } else {
                    res.status(202).send(key);
                }
            });
        }
    });
});

app.post("/api/reset", (req, res) => {
    const key = req.body.key;
    const password = req.body.password;
    db.execute(`SELECT * FROM user WHERE password = ?`, [key], (e, r) => {
        if (e || !Array.isArray(r) || !r.length) {
            console.error('Reset error:', e ? e : r);
            res.sendStatus(503);
        }
        const salt = r[0].name_last + r[0].student_id + r[0].username + r[0].name_first;
        const saltedPassword = pbkdf2Sync(password, salt, ITERATIONS, KEYLEN, DIGEST).toString('hex');
        db.execute(`UPDATE user SET password = ? WHERE student_id = ?`, [saltedPassword, r[0].student_id], (err, _result) => {
            if (err) {
                console.error('Reset update error:', err);
                res.sendStatus(503);
            } else {
                res.status(202).send('Password has been reset');
            }
        });
    });
});

app.post('/api/outbox', (req, res) => {
    const { name, photo, status } = req.body;
    //console.log(req);
    db.execute(`INSERT INTO messages (name, photo, status) VALUES (?, ?, ?)`, [name, photo, status], (err, _result) => {
        if (err) {
            console.error(err);
            res.sendStatus(500);
        } else {
            res.status(201).send('Message created and sent');
        }
    });
});

app.post('/api/inbox', (req, res) => {
    const name = req.body;
    db.execute(`SELECT * FROM messages WHERE name = ?`, [name], (err, result) => {
        if (err) {
            console.error(err);
            res.sendStatus(500);
        } else {
            res.status(200).json(result);
        }
    })
})

app.listen(PORT, () => {
    console.log(`Server running on ${PORT}`);
    db.query(`SET SESSION wait_timeout = 28800`);
})
