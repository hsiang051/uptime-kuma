const NotificationProvider = require("./notification-provider");
const { log } = require("../../src/util");

const sdk = require("matrix-js-sdk");
const fs = require("fs");
const path = require("path");

const { CryptoEvent } = require("matrix-js-sdk/lib/crypto-api");
const { IDBFactory, IDBKeyRange } = require("fake-indexeddb");

const DATA_DIR = path.join(process.cwd(), "data", "matrix");

// ── IndexedDB serialization helpers ─────────────────────────────────────────
// Generated with assistance by Claude (Anthropic)

/** Wrap an IDBRequest in a Promise */
function idbReq(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/** JSON-stringify with Uint8Array support (stored as base64) */
function idbSerialize(data) {
    return JSON.stringify(data, (_key, value) => {
        if (value instanceof Uint8Array) {
            return { _t: "u8", d: Buffer.from(value).toString("base64") };
        }
        return value;
    }, 2);
}

/** JSON-parse with Uint8Array support */
function idbDeserialize(str) {
    return JSON.parse(str, (_key, value) => {
        if (value && value._t === "u8") {
            return new Uint8Array(Buffer.from(value.d, "base64"));
        }
        return value;
    });
}

/** Export all databases in an IDBFactory to a plain object */
async function exportIDB(factory) {
    const dbs = await factory.databases();
    const out = {};

    for (const { name, version } of dbs) {
        const db = await new Promise((res, rej) => {
            const req = factory.open(name, version);
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
        });

        const storeNames = Array.from(db.objectStoreNames);
        const stores = {};

        if (storeNames.length > 0) {
            const tx = db.transaction(storeNames, "readonly");
            for (const storeName of storeNames) {
                const store = tx.objectStore(storeName);
                const indexes = {};
                for (const indexName of Array.from(store.indexNames)) {
                    const idx = store.index(indexName);
                    indexes[indexName] = {
                        keyPath: idx.keyPath,
                        multiEntry: idx.multiEntry,
                        unique: idx.unique,
                    };
                }
                const keys = await idbReq(store.getAllKeys());
                const values = await idbReq(store.getAll());
                stores[storeName] = {
                    keyPath: store.keyPath,
                    autoIncrement: store.autoIncrement,
                    indexes,
                    records: keys.map((k, i) => ({ k, v: values[i] })),
                };
            }
        }

        db.close();
        out[name] = { version, stores };
    }
    return out;
}

/** Restore databases into an IDBFactory from a previously exported object */
async function importIDB(factory, data) {
    for (const [dbName, { version, stores }] of Object.entries(data)) {
        const db = await new Promise((res, rej) => {
            const req = factory.open(dbName, version);
            req.onupgradeneeded = (event) => {
                const upgradeDb = event.target.result;
                for (const [storeName, { keyPath, autoIncrement, indexes }] of Object.entries(stores)) {
                    if (!upgradeDb.objectStoreNames.contains(storeName)) {
                        const store = upgradeDb.createObjectStore(storeName, {
                            keyPath: keyPath !== null ? keyPath : undefined,
                            autoIncrement,
                        });
                        for (const [idxName, { keyPath: idxKP, multiEntry, unique }] of Object.entries(indexes)) {
                            store.createIndex(idxName, idxKP, { multiEntry, unique });
                        }
                    }
                }
            };
            req.onsuccess = () => res(req.result);
            req.onerror = () => rej(req.error);
        });

        const storeNames = Object.keys(stores);
        if (storeNames.length > 0) {
            const tx = db.transaction(storeNames, "readwrite");
            for (const [storeName, { keyPath, records }] of Object.entries(stores)) {
                const store = tx.objectStore(storeName);
                for (const { k, v } of records) {
                    // Inline key (keyPath defined): put(value)
                    // Out-of-line key (keyPath null): put(value, key)
                    if (keyPath !== null && keyPath !== undefined) {
                        store.put(v);
                    } else {
                        store.put(v, k);
                    }
                }
            }
            await new Promise((res, rej) => {
                tx.oncomplete = res;
                tx.onerror = () => rej(tx.error);
            });
        }

        db.close();
    }
}

// ────────────────────────────────────────────────────────────────────────────

class MatrixEncrypted extends NotificationProvider {
    name = "matrix-encrypted";

    // Singleton client
    static client = null;
    static idbFactory = null;
    static idbFile = null;

    async send(notification, msg) {
        const okMsg = "Sent Successfully.";

        // Initialize client once
        if (!MatrixEncrypted.client) {
            if (!fs.existsSync(DATA_DIR)) {
                fs.mkdirSync(DATA_DIR, { recursive: true });
            }

            // Each userId gets its own IDB file
            const safeId = notification.userId.replace(/[^a-zA-Z0-9_.-]/g, "_");
            MatrixEncrypted.idbFile = path.join(DATA_DIR, `${safeId}-idb.json`);
            MatrixEncrypted.idbFactory = new IDBFactory();

            // Restore saved crypto state (device keys, sessions, verification state)
            if (fs.existsSync(MatrixEncrypted.idbFile)) {
                log.info("Matrix", "Restoring crypto state from disk...");
                try {
                    const saved = idbDeserialize(fs.readFileSync(MatrixEncrypted.idbFile, "utf-8"));
                    await importIDB(MatrixEncrypted.idbFactory, saved);
                    log.info("Matrix", "Crypto state restored.");
                } catch (err) {
                    log.warn("Matrix", `Failed to restore crypto state: ${err.message}. Starting fresh.`);
                }
            }

            // Expose our factory as the global IndexedDB before the SDK initialises
            global.indexedDB = MatrixEncrypted.idbFactory;
            global.IDBKeyRange = IDBKeyRange;

            MatrixEncrypted.client = sdk.createClient({
                baseUrl: notification.homeserverUrl,
                accessToken: notification.accessToken,
                userId: notification.userId,
                deviceId: notification.deviceId,
            });

            // useIndexedDB: true  →  SDK persists all keys in our fake-indexeddb
            await MatrixEncrypted.client.initRustCrypto({ useIndexedDB: true });

            // Listen for verification requests
            this.listenForVerificationRequests(MatrixEncrypted.client);

            // Start client
            await MatrixEncrypted.client.startClient({ initialSyncLimit: 1 });

            // Wait for initial sync
            await new Promise((resolve) => {
                MatrixEncrypted.client.once("sync", (state) => {
                    if (state === "PREPARED") resolve();
                });
            });

            // Persist crypto state to disk after initial sync
            await this._saveIDB();

            log.info("Matrix", "Client initialized and ready");
        } else {
            log.info("Matrix", "Reusing existing client instance");
        }

        log.info("Matrix", `Checking membership for room ${notification.internalRoomId}...`);

        let room = MatrixEncrypted.client.getRoom(notification.internalRoomId);
        const membership = room ? room.getMyMembership() : null;

        if (membership !== "join") {
            log.info("Matrix", `Bot is not in the room (current status: ${membership || "unknown"}). Attempting to join...`);
            try {
                await MatrixEncrypted.client.joinRoom(notification.internalRoomId);
                log.info("Matrix", "Successfully joined the room!");
                room = MatrixEncrypted.client.getRoom(notification.internalRoomId);
            } catch (err) {
                throw new Error(`Cannot join room ${notification.internalRoomId}. Did you invite the bot? \nError: ${err.message}`);
            }
        }

        log.info("Matrix", "Sending encrypted message…");

        // Wait until OlmMachine has processed the room's m.room.encryption state event
        const crypto = MatrixEncrypted.client.getCrypto();
        for (let i = 0; i < 20; i++) {
            if (await crypto.isEncryptionEnabledInRoom(notification.internalRoomId)) break;
            await new Promise((r) => setTimeout(r, 500));
        }

        await MatrixEncrypted.client.sendMessage(notification.internalRoomId, {
            msgtype: "m.text",
            body: msg,
        });

        return okMsg;
    }

    async _saveIDB() {
        try {
            const data = await exportIDB(MatrixEncrypted.idbFactory);
            fs.writeFileSync(MatrixEncrypted.idbFile, idbSerialize(data), { mode: 0o600 });
            log.info("Matrix", "Crypto state saved to disk.");
        } catch (err) {
            log.warn("Matrix", `Failed to save crypto state: ${err.message}`);
        }
    }

    listenForVerificationRequests(client) {
        // Coded with assistance by Devin and DeepWiki

        // 1. Listen for incoming verification requests
        client.on(CryptoEvent.VerificationRequestReceived, async (request) => {
            // 2. Accept the verification request
            await request.accept();

            // 3. Wait for other party to choose SAS method and start verification
            request.once("change", async () => {
                // phase 4 is "started"
                if (request.phase === 4 && request.chosenMethod === "m.sas.v1") {
                    const verifier = request.verifier;

                    // 4. Start verification
                    const verificationPromise = verifier.verify();

                    // 5. Confirm SAS
                    verifier.once("show_sas", async (showSasCallbacks) => {
                        // delay mostly added for tests
                        setTimeout(() => {
                            showSasCallbacks.confirm();
                        }, 5000);
                    });

                    // 6. Wait for verification to complete
                    await verificationPromise;

                    // Save verification state so it persists across restarts
                    await this._saveIDB();
                }
            });
        });
    }
}

module.exports = MatrixEncrypted;
