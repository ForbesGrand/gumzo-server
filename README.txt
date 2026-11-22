Gumzo update: Gold theme + carrier SMS

Files
- index.html: updated app interface and carrier SMS option
- server.js: latest server file from the supplied ZIP (unchanged)

What SMS does
In a one-to-one chat, open the three-dot menu and choose “Send an SMS using my phone plan.” Gumzo opens the phone's normal Messages app with the contact and any typed draft filled in. The user still taps Send. This uses the phone carrier's SMS service and may use an SMS bundle or cost normal SMS credit. It does not need internet to send that SMS, but both people need phone service and a working phone number. SMS replies appear in the phone's Messages app, not inside Gumzo. Group and shop chats do not have this option.

To publish
Upload index.html and server.js to the same GitHub repository used by the Gumzo server, replacing the old files, then let the hosting service redeploy. The server.js file is included for convenience but was not changed for this feature. Keep your repository's existing package.json, manifest.json, and other files.
