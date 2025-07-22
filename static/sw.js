// Define a new cache name to force a complete update
const CACHE_NAME = 'farm-manager-cache-v6-simple-test';

// A minimal list of files to cache. We will only cache the root and main CSS/JS
const URLS_TO_CACHE = [
  '/',
  '/static/css/style.css',
  '/static/js/main.js'
];

// Standard install event - no changes here
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('SIMPLE TEST: Caching app shell');
        return cache.addAll(URLS_TO_CACHE);
      })
  );
});

// Standard activate event - no changes here
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

// SIMPLEST POSSIBLE FETCH HANDLER
// This is the "Cache First" strategy for ALL requests.
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // If we find a match in the cache, return it.
        // If not, try to fetch it from the network.
        return response || fetch(event.request);
      })
  );
});