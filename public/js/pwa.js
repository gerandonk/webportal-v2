// Register Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/js/service-worker.js')
      .then((registration) => {
        console.log('ServiceWorker registration successful with scope:', registration.scope);
      })
      .catch((error) => {
        console.error('ServiceWorker registration failed:', error);
      });
  });

  // Optional: Listen for any messages from the service worker
  navigator.serviceWorker.addEventListener('message', (event) => {
    console.log('Message from service worker:', event.data);
  });
}
