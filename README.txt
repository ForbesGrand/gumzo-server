Gumzo update: Customer support, chat recovery requests, and admin report inbox

Files
- index.html: updated Gumzo app screen
- server.js: adds support requests, report review, staff inbox, and chat recovery for messages still stored by Gumzo

How users ask for help
In Gumzo, open the three-dot menu, choose Help & support, fill in the form, and tap Send to support. They can check replies and request status in the same screen. For chat recovery, choose Restore a deleted chat and enter the other person's Gumzo username or the group ID (for example g:12).

Where the owner sees requests and reports
Set the Render environment variable ADMIN_USER to the exact username of the Gumzo account that should manage support. In Render, open your Gumzo service, go to Environment, add ADMIN_USER, save, and redeploy. Then sign in to Gumzo with that account, open the three-dot menu > Help & support > Open staff inbox. The inbox contains help requests, chat/status reports, and Community Board reports. The admin can reply, close requests, mark reports reviewed, and restore available chat messages.

Deploying this update
Replace index.html and server.js in the existing GitHub project with these copies, commit/push the changes, and let Render deploy. Keep your existing package.json, manifest.json, service worker, and other project files. The server adds its support/report database columns and table when it starts; no manual SQL step is needed.

Recovery limits
Gumzo can unhide messages deleted only from the requester's side, or clear their chat's hidden/cleared markers, while the original message still exists. A message deleted for everyone has its text erased and its attachment removed, so it cannot be restored. Expired/disappearing messages and data from a deleted account also cannot be restored. Recovery is performed by the admin from the support request.

This package contains source files only. It has not been deployed to Render. The staff inbox stays locked until ADMIN_USER is set.
