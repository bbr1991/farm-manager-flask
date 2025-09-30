// static/js/database.js

// This is the "engine" for our offline database.

const DB_NAME = 'FarmAppDB';
const DB_VERSION = 1;
const STORE_NAME = 'pending_transactions';

let db;

function openDatabase() {
    return new Promise((resolve, reject) => {
        if (db) {
            return resolve(db);
        }

        console.log('Opening offline database...');
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = (event) => {
            console.error('Database error:', event.target.error);
            reject('Error opening database');
        };

        request.onsuccess = (event) => {
            db = event.target.result;
            console.log('Offline database opened successfully.');
            resolve(db);
        };

        // This event only runs when the database is first created or the version changes.
        request.onupgradeneeded = (event) => {
            const tempDb = event.target.result;
            console.log('Upgrading database...');
            if (!tempDb.objectStoreNames.contains(STORE_NAME)) {
                // We create a "store" (like a table) to hold our transactions.
                // 'id' will be the auto-incrementing primary key.
                tempDb.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
                console.log('Object store "pending_transactions" created.');
            }
        };
    });
}

// Function to save a transaction to the offline database.
async function saveTransactionOffline(transactionData) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        // We start a "readwrite" transaction on our store.
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        
        // Add the data to the store.
        const request = store.add(transactionData);

        request.onsuccess = () => {
            console.log('Transaction saved offline:', transactionData);
            resolve(request.result); // Returns the new ID
        };
        request.onerror = (event) => {
            console.error('Error saving transaction offline:', event.target.error);
            reject('Error saving transaction');
        };
    });
}

// Function to get all the transactions that are waiting to be synced.
async function getAllPendingTransactions() {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.getAll();

        request.onsuccess = () => {
            resolve(request.result);
        };
        request.onerror = (event) => {
            console.error('Error getting pending transactions:', event.target.error);
            reject('Error getting transactions');
        };
    });
}

// Function to delete a transaction after it has been successfully synced.
async function deletePendingTransaction(id) {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.delete(id);

        request.onsuccess = () => {
            console.log('Transaction deleted from offline store, ID:', id);
            resolve();
        };
        request.onerror = (event) => {
            console.error('Error deleting pending transaction:', event.target.error);
            reject('Error deleting transaction');
        };
    });
}