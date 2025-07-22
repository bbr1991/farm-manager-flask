// Define a name for our cache
const CACHE_NAME = 'farm-manager-cache-v4';

// List all the files that make up the "app shell"
// These are the files that will be saved so the app can load offline
const URLS_TO_CACHE = [
  '/', // The root of our site (the login page)
  '/dashboard', // The main dashboard page
  '/static/css/style.css',
  '/static/js/main.js',
  '/static/js/dashboard.js',
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png'
];

// The 'install' event is fired when the service worker is first installed.
self.addEventListener('install', function(event) {
  console.log('Service Worker: Installing...');
  // We tell the browser to wait until our cache is populated
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) {
        console.log('Service Worker: Caching app shell...');
        return cache.addAll(URLS_TO_CACHE);
      })
  );
});

// The 'activate' event is fired after installation.
// It's a good place to clean up old caches.
self.addEventListener('activate', function(event) {
  console.log('Service Worker: Activating...');
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.map(function(cacheName) {
          if (cacheName !== CACHE_NAME) {
            console.log('Service Worker: Deleting old cache', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// The 'fetch' event is fired every time the app makes a network request (e.g., for a page, a CSS file, an image).
self.addEventListener('fetch', function(event) {
  console.log('Service Worker: Fetching', event.request.url);
  event.respondWith(
    // We first check if the requested file is in our cache.
    caches.match(event.request)
      .then(function(response) {
        // If it is in the cache, we return it immediately.
        if (response) {
          console.log('Service Worker: Found in cache', event.request.url);
          return response;
        }
        // If it's not in the cache, we try to fetch it from the network.
        console.log('Service Worker: Not in cache, fetching from network', event.request.url);
        return fetch(event.request);
      }
    )
  );
});
// Listen for the 'sync' event
self.addEventListener('sync', function(event) {
    console.log('Service Worker: Sync event fired.', event.tag);
    if (event.tag === 'sync-new-expenses') {
        console.log('Service Worker: Syncing new expenses...');
        event.waitUntil(syncNewExpenses());
    }
});

// Function to handle the synchronization
function syncNewExpenses() {
    // We need to import the idb script because the service worker runs in a different context
    importScripts('/static/js/idb.js');
    
    return getPendingExpenses().then(expenses => {
        const syncPromises = expenses.map(expense => {
            console.log('Attempting to sync expense:', expense);
            
            return fetch('/api/sync/expense', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(expense),
            })
            .then(response => {
                if (response.ok) {
                    console.log('Expense synced successfully, deleting from local DB');
                    return deletePendingExpense(expense.id);
                } else {
                    // If the server returns an error (e.g., 400, 500), we don't delete the local copy
                    console.error('Server returned an error, will retry later.');
                    return Promise.reject('Server error');
                }
            })
            .catch(err => {
                // If there's a network error, we don't delete the local copy
                console.error('Network error during sync, will retry later.', err);
                return Promise.reject('Network error');
            });
        });
        return Promise.all(syncPromises);
    });
}