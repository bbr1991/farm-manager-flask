// sw.js (Service Worker)

// Import the database functions we just created.
importScripts('/static/js/database.js');

const CACHE_NAME = 'farm-app-cache-v1';
const URLS_TO_CACHE = [
    '/',
    '/static/css/style.css',
    '/static/js/main.js',
    '/static/js/database.js'
    // We will add more pages to cache later
];

// 1. Installation: Cache the basic app shell
self.addEventListener('install', event => {
    console.log('Service Worker: Installing...');
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Service Worker: Caching app shell...');
                return cache.addAll(URLS_TO_CACHE);
            })
    );
});

// 2. Activation: Clean up old caches
self.addEventListener('activate', event => {
    console.log('Service Worker: Activating...');
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cache => {
                    if (cache !== CACHE_NAME) {
                        console.log('Service Worker: Clearing old cache', cache);
                        return caches.delete(cache);
                    }
                })
            );
        })
    );
});

// 3. Fetch: Serve from cache if available
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                return response || fetch(event.request);
            })
    );
});

// 4. THIS IS THE MOST IMPORTANT PART: The Sync Logic
self.addEventListener('sync', event => {
    console.log('Service Worker: Sync event triggered!', event);
    // The browser has told us it's online and ready to sync.
    // We gave our sync the tag 'sync-pending-expenses'.
    if (event.tag === 'sync-pending-expenses') {
        event.waitUntil(syncPendingExpenses());
    }
});

// This is the function that will run when the sync event is triggered.
async function syncPendingExpenses() {
    console.log('Service Worker: Starting to sync pending expenses...');
    try {
        const pendingExpenses = await getAllPendingTransactions();
        
        if (pendingExpenses.length === 0) {
            console.log('No pending expenses to sync.');
            return;
        }

        console.log(`Found ${pendingExpenses.length} expenses to sync.`);

        // We use Promise.all to try and send all of them.
        await Promise.all(pendingExpenses.map(async (expense) => {
            try {
                const response = await fetch('/api/sync/expense', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(expense.data)
                });

                if (response.ok) {
                    console.log('Successfully synced expense with server, ID:', expense.id);
                    // If the server confirms it was saved, delete it from our offline store.
                    await deletePendingTransaction(expense.id);
                } else {
                    console.error('Server responded with an error for expense ID:', expense.id, await response.json());
                }
            } catch (error) {
                console.error('Network error while syncing expense ID:', expense.id, error);
                // If one fails, we just leave it in the DB to try again next time.
            }
        }));
        
        console.log('Sync process completed.');

    } catch (error) {
        console.error('Error during the sync process:', error);
    }
}