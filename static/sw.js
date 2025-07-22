const CACHE_NAME = 'farm-manager-cache-v7-full';

const URLS_TO_CACHE = [
  '/', 
  '/dashboard',
  '/static/css/style.css',
  '/static/js/main.js',
  '/static/js/dashboard.js', // We can cache this again now
  '/static/js/idb.js',
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(URLS_TO_CACHE))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

self.addEventListener('fetch', (event) => {
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => {
                return caches.open(CACHE_NAME).then((cache) => {
                    return cache.match('/dashboard').then(response => {
                       return response || cache.match('/');
                    });
                });
            })
        );
    } else {
        event.respondWith(
            caches.match(event.request).then((response) => {
                return response || fetch(event.request);
            })
        );
    }
});

self.addEventListener('sync', function(event) {
    if (event.tag === 'sync-new-expenses') {
        event.waitUntil(syncNewExpenses());
    }
});

function syncNewExpenses() {
    importScripts('/static/js/idb.js');
    return getPendingExpenses().then(expenses => {
        const syncPromises = expenses.map(expense => {
            return fetch('/api/sync/expense', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(expense),
            })
            .then(response => {
                if (response.ok) {
                    return deletePendingExpense(expense.id);
                } else {
                    return Promise.reject('Server error');
                }
            })
            .catch(err => {
                return Promise.reject('Network error');
            });
        });
        return Promise.all(syncPromises);
    });
}