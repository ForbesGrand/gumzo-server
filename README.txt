Gumzo update: Country flag display fix

Replace index.html and server.js in your Gumzo GitHub project with these files. Keep your existing package.json, manifest.json, service worker, and other files. The server.js is included so this package contains the full current Gumzo source; it was not changed for the flag display update.

Country flags in the emoji picker now use small lazy-loaded SVG images, so the picker shows actual flags even if the phone cannot draw flag emoji. Messages, chat previews, Community Board posts, and status text also display flag pictures when they contain a country flag emoji. The saved/sent text remains the standard Unicode flag emoji.

Flag pictures load from FlagCDN (flagcdn.io), so the first display of each flag needs internet. The images are small and loaded as needed. The picker falls back to the country code text if the image cannot load.
