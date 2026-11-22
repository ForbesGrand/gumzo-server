Gumzo update: Community Board + Emoji picker

Replace these two files in the Gumzo GitHub project:
- index.html
- server.js

Keep your existing package.json, manifest.json, service worker, and other project files. The new Board tables are created automatically when the server starts; they use the same PostgreSQL database as the app.

Community Board
- Open Board from the app's top bar.
- Posts are text-only and up to 500 characters, with an area and a post type: Announcement, Event, For sale, or Help.
- Posts are visible to signed-in Gumzo users. You can filter by area; leave the filter blank to see all areas.
- You can chat with the author, remove your own post, or report someone else's post.
- The app shows recent posts from the last 90 days, with up to 100 posts per request. Each account can post up to 10 times per hour.

Emojis
- Open the smiley button in a chat to browse emoji categories or search common emoji names.
- The picker uses the phone's built-in color emoji and briefly animates the emoji when selected. Emoji appearance varies a little by phone.
- Message reactions include more choices too.
