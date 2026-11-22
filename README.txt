Gumzo update: Voice, status replies, compose, chat selection, and emoji fix

Replace index.html and server.js in the Gumzo GitHub project with these files. Keep your existing package.json, manifest.json, service worker, and other files. The included server.js keeps the Community Board database setup from the previous update; the new voice/status/chat-list controls are in index.html.

What changed
- The voice-note control now uses a microphone outline similar to modern voice-message apps. It pulses while recording and shows a stop button to finish and send.
- Viewers can react to or report a status, and can reply. A status reply is sent as a normal direct message with the status context, so it appears in the status owner's Gumzo inbox/chat.
- A floating pencil button opens shortcuts for New chat, New group, New status, New community post, and Settings.
- Use the top menu's “Select chats” option, then tap chats. You can also long-press/right-click a chat. The selection bar offers pin, archive/unarchive, read/unread, delete, or Done.
- The emoji grid now loads when a chat opens and has a fixed scroll area so emoji results remain visible. It includes the categorized picker and selection animation from the previous update.

Status replies need Gumzo internet connection to send; they are app messages, not carrier SMS. Reports are recorded by the existing report system.
