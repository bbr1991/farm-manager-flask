// Define a name for our cache. Changing this version will trigger a new install.
const CACHE_NAME = 'farm-manager-cache-v8-final';

// List all the files that make up the "app shell"
const URLS_TO_CACHE = [
  '/', 
  '/dashboard',
  '/static/css/style.css',
  '/static/js/main.js',
  '/static/js/dashboard.js',
  '/static/js/idb.js',
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png'
];

// The 'install' event: fires when the service worker is first installed.
self.addEventListener('install', event => {
  console.log('Service Worker: Installing...');
  // Wait until the cache is populated.
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service Worker: Caching app shell...');
        return cache.addAll(URLS_TO_CACHE);
      })
  );
});

// The 'activate' event: fires after installation. Good for cleaning up old caches.
self.addEventListener('activate', event => {
  console.log('Service Worker: Activating...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          // If a cache is not our current one, delete it.
          if (cacheName !== CACHE_NAME) {
            console.log('Service Worker: Deleting old cache', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// The 'fetch' event: fires every time the app makes a network request.
// STRATEGY: Cache First. This is the most reliable for offline functionality.
self.addEventListener('fetch', event => {
  event.respondWith(
    // First, look in the cache for a match for the request.
    caches.match(event.request)
      .then(response => {
        // If we find a match in the cache (response is not null), return it. This is fast.
        // If there's no match, then we must try to fetch it from the network.
        return response || fetch(event.request);
      })
  );
});

// The 'sync' event: fires when a background sync is triggered.
self.addEventListener('sync', function(event) {
    console.log('Service Worker: Sync event fired.', event.tag);
    if (event.tag === 'sync-new-expenses') {
        console.log('Service Worker: Syncing new expenses...');
        event.waitUntil(syncNewExpenses());
    }
});

// Function to handle the synchronization of offline data
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
                    // If the server returns an error, we don't delete the local copy to retry later
                    console.error('Server returned an error, will retry later.');
                    return Promise.reject('Server error');
                }
            })
            .catch(err => {
                // If there's a network error, we don't delete the local copy to retry later
                console.error('Network error during sync, will retry later.', err);
                return Promise.reject('Network error');
            });
        });
        return Promise.all(syncPromises);
    });
}