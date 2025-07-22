// This is the simplest possible service worker.
// It does absolutely nothing. Its only purpose is to register successfully.

self.addEventListener('install', (event) => {
  console.log('V7 Simple Install: Success!');
});

self.addEventListener('activate', (event) => {
  console.log('V7 Simple Activate: Success!');
});

self.addEventListener('fetch', (event) => {
  // Do nothing. Just go to the network.
  return;
});