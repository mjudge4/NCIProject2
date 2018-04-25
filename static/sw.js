//names the current sw cache version to be used
var staticCacheName = 'babiesgrow-static-v5';


//installs the service worker
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(staticCacheName).then(function(cache) {
            return cache.addAll([
                '/',
                '/offerings/',
                '/static/js/offerings.js',
                '/static/css/bootstrap.min.css'
            ]);
        })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.filter(function(cacheName) {
                    return cacheName.startsWith('babiesgrow-') &&
                        cacheName != staticCacheName;
                }).map(function(cacheName) {
                    return caches.delete(cacheName);
                })
            );
        })
    );
});

//@ https://jakearchibald.com/2014/offline-cookbook/
self.addEventListener('fetch', function(event) {
  event.respondWith(
    // Try the cache
    caches.match(event.request).then(function(response) {
      // Fall back to network
      return response || fetch(event.request);
    }).catch(function() {
      // If both fail, show a generic fallback:
      return "Oooops, you're offline";
      // However, in reality you'd have many different
      // fallbacks, depending on URL & headers.
      // Eg, a fallback silhouette image for avatars.
    })
  );
});



/*
self.addEventListener('fetch', function (event) {
    event.respondWith(
        fetch(event.request).then(function (response) {
            if (response.status === 404) {
                return new Response("Hmmm, page not found");
            }
            return response;
        }).catch(function () {
            return new Response("Whatever you tried to do, it did not work");
        })
    );
});

*/