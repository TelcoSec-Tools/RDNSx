// Service Worker for RDNSx Documentation PWA
// https://rdnsx.telcosec.net/sw.js

const CACHE_NAME = 'rdnsx-docs-v1.0.0';
const STATIC_CACHE = 'rdnsx-static-v1.0.0';
const DYNAMIC_CACHE = 'rdnsx-dynamic-v1.0.0';

// Files to cache immediately
const STATIC_ASSETS = [
  '/',
  '/guide/quick-start/',
  '/api/cli-reference/',
  '/guide/installation/',
  '/assets/css/style.css',
  '/manifest.json',
  '/sitemap.xml',
  '/robots.txt'
];

// Install event - cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => {
        return self.skipWaiting();
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      return self.clients.claim();
    })
  );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip external requests
  if (!url.origin.includes('docs.rdnsx.dev') && !url.origin.includes('localhost')) return;

  // Handle API requests differently
  if (url.pathname.startsWith('/api/') || url.pathname.includes('search')) {
    event.respondWith(
      caches.open(DYNAMIC_CACHE).then(cache => {
        return fetch(request).then(response => {
          // Cache successful responses
          if (response.status === 200) {
            cache.put(request, response.clone());
          }
          return response;
        }).catch(() => {
          // Return cached version if available
          return cache.match(request);
        });
      })
    );
    return;
  }

  // Default caching strategy: Cache First, then Network
  event.respondWith(
    caches.match(request).then(cachedResponse => {
      if (cachedResponse) {
        // Return cached version and update in background
        fetch(request).then(response => {
          if (response.status === 200) {
            caches.open(DYNAMIC_CACHE).then(cache => {
              cache.put(request, response);
            });
          }
        }).catch(() => {
          // Network failed, serve cached version
        });
        return cachedResponse;
      }

      // Not in cache, fetch from network
      return fetch(request).then(response => {
        // Don't cache non-successful responses
        if (response.status !== 200) {
          return response;
        }

        // Cache the response
        const responseClone = response.clone();
        caches.open(DYNAMIC_CACHE).then(cache => {
          cache.put(request, responseClone);
        });

        return response;
      }).catch(() => {
        // Network failed and not in cache
        if (request.destination === 'document') {
          // Return offline page for navigation requests
          return caches.match('/offline.html').then(response => {
            return response || new Response('Offline - Please check your connection', {
              status: 503,
              statusText: 'Service Unavailable'
            });
          });
        }
      });
    })
  );
});

// Background sync for analytics (if implemented)
self.addEventListener('sync', event => {
  if (event.tag === 'background-sync') {
    event.waitUntil(doBackgroundSync());
  }
});

function doBackgroundSync() {
  // Placeholder for background sync functionality
  // Could be used for analytics, form submissions, etc.
  return Promise.resolve();
}

// Push notifications (if implemented)
self.addEventListener('push', event => {
  if (event.data) {
    const data = event.data.json();
    const options = {
      body: data.body,
      icon: '/assets/images/icon-192.png',
      badge: '/assets/images/icon-192.png',
      data: data.url
    };

    event.waitUntil(
      self.registration.showNotification(data.title, options)
    );
  }
});

// Handle notification clicks
self.addEventListener('notificationclick', event => {
  event.notification.close();

  event.waitUntil(
    clients.openWindow(event.notification.data || '/')
  );
});