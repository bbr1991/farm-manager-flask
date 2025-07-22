const DB_NAME = 'farm-db';
const DB_VERSION = 1;
const EXPENSE_STORE_NAME = 'pending_expenses';
let db;

// Function to open the database
function openDb() {
    return new Promise((resolve, reject) => {
        if (db) {
            return resolve(db);
        }
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = (event) => {
            console.error("Database error:", event.target.error);
            reject("Database error");
        };

        request.onupgradeneeded = (event) => {
            console.log("Database upgrade needed.");
            const db = event.target.result;
            if (!db.objectStoreNames.contains(EXPENSE_STORE_NAME)) {
                db.createObjectStore(EXPENSE_STORE_NAME, { keyPath: 'id', autoIncrement: true });
                console.log("Created object store:", EXPENSE_STORE_NAME);
            }
        };

        request.onsuccess = (event) => {
            console.log("Database opened successfully.");
            db = event.target.result;
            resolve(db);
        };
    });
}

// Function to save an expense to the local database
function saveExpense(expense) {
    return openDb().then(db => {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([EXPENSE_STORE_NAME], 'readwrite');
            const store = transaction.objectStore(EXPENSE_STORE_NAME);
            store.add(expense);
            transaction.oncomplete = () => {
                console.log("Expense saved to IndexedDB.");
                resolve();
            };
            transaction.onerror = (event) => {
                console.error("Error saving expense:", event.target.error);
                reject(event.target.error);
            };
        });
    });
}

// Function to get all pending expenses
function getPendingExpenses() {
    return openDb().then(db => {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([EXPENSE_STORE_NAME], 'readonly');
            const store = transaction.objectStore(EXPENSE_STORE_NAME);
            const request = store.getAll();
            request.onsuccess = () => {
                resolve(request.result);
            };
            request.onerror = (event) => {
                reject(event.target.error);
            };
        });
    });
}

// Function to delete a synced expense
function deletePendingExpense(id) {
    return openDb().then(db => {
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([EXPENSE_STORE_NAME], 'readwrite');
            const store = transaction.objectStore(EXPENSE_STORE_NAME);
            store.delete(id);
            transaction.oncomplete = () => {
                console.log("Expense deleted from IndexedDB:", id);
                resolve();
            };
            transaction.onerror = (event) => {
                reject(event.target.error);
            };
        });
    });
}