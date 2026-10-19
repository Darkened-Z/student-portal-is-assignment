const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'portal.db');

function getDb() {
    return new Database(DB_PATH);
}

function initDb() {
    const db = new Database(DB_PATH);
    const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
    db.exec(schema);
    const seed = fs.readFileSync(path.join(__dirname, 'seed.sql'), 'utf8');
    db.exec(seed);
    db.close();
    console.log('[db] Initialised at', DB_PATH);
}

module.exports = { getDb, initDb };
