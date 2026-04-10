/**
 * mock-server.mjs — Lightweight Express-free mock API for local UI testing.
 * Implements enough of the Signal REST API for a full login + messaging flow.
 *
 * Usage: node mock-server.mjs
 * Listens on port 3001 by default.
 */

import http from 'node:http';

const PORT = 3001;

let registered = false;
const sessionId = 'mock-session-001';

const conversations = [
  {
    id: 1, conversationId: 'conv-1', type: 1, name: 'Alice Smith',
    unreadCount: 2, lastMessageTimestamp: Date.now(),
    lastMessageBody: 'Hey there! How are you?', isPinned: false, isArchived: false,
  },
  {
    id: 2, conversationId: 'conv-2', type: 1, name: 'Bob Jones',
    unreadCount: 0, lastMessageTimestamp: Date.now() - 3_600_000,
    lastMessageBody: 'See you later', isPinned: false, isArchived: false,
  },
  {
    id: 3, conversationId: 'conv-3', type: 1, name: 'Charlie Davis',
    unreadCount: 5, lastMessageTimestamp: Date.now() - 7_200_000,
    lastMessageBody: 'Check out this link!', isPinned: false, isArchived: false,
  },
  {
    id: 4, conversationId: 'conv-4', type: 1, name: 'Team Engineering',
    unreadCount: 0, lastMessageTimestamp: Date.now() - 86_400_000,
    lastMessageBody: 'Meeting at 3pm tomorrow', isPinned: false, isArchived: false,
  },
];

const messagesByConv = {
  'conv-1': [
    { id: 1, guid: 'msg-1a', conversationId: 'conv-1', sourceUuid: 'alice-uuid', timestamp: Date.now() - 300_000, type: 1, body: 'Hey there! How are you?', isRead: true, sendState: 2 },
    { id: 2, guid: 'msg-1b', conversationId: 'conv-1', sourceUuid: 'me-uuid', timestamp: Date.now() - 240_000, type: 2, body: "I'm doing great, thanks!", isRead: true, sendState: 3 },
    { id: 3, guid: 'msg-1c', conversationId: 'conv-1', sourceUuid: 'alice-uuid', timestamp: Date.now() - 180_000, type: 1, body: 'Want to grab coffee later?', isRead: true, sendState: 2 },
    { id: 4, guid: 'msg-1d', conversationId: 'conv-1', sourceUuid: 'me-uuid', timestamp: Date.now() - 120_000, type: 2, body: 'Sure! How about 3pm at the usual place?', isRead: true, sendState: 3 },
    { id: 5, guid: 'msg-1e', conversationId: 'conv-1', sourceUuid: 'alice-uuid', timestamp: Date.now() - 60_000, type: 1, body: 'Perfect, see you then! ☕', isRead: true, sendState: 2 },
  ],
  'conv-2': [
    { id: 10, guid: 'msg-2a', conversationId: 'conv-2', sourceUuid: 'bob-uuid', timestamp: Date.now() - 7_200_000, type: 1, body: 'Are we still on for Friday?', isRead: true, sendState: 2 },
    { id: 11, guid: 'msg-2b', conversationId: 'conv-2', sourceUuid: 'me-uuid', timestamp: Date.now() - 7_100_000, type: 2, body: 'Yes! Looking forward to it.', isRead: true, sendState: 3 },
    { id: 12, guid: 'msg-2c', conversationId: 'conv-2', sourceUuid: 'bob-uuid', timestamp: Date.now() - 3_600_000, type: 1, body: 'See you later', isRead: true, sendState: 2 },
  ],
  'conv-3': [
    { id: 20, guid: 'msg-3a', conversationId: 'conv-3', sourceUuid: 'charlie-uuid', timestamp: Date.now() - 7_200_000, type: 1, body: 'Check out this link!', isRead: false, sendState: 2 },
  ],
  'conv-4': [
    { id: 30, guid: 'msg-4a', conversationId: 'conv-4', sourceUuid: 'team-uuid', timestamp: Date.now() - 90_000_000, type: 1, body: 'Sprint planning moved to Tuesday', isRead: true, sendState: 2 },
    { id: 31, guid: 'msg-4b', conversationId: 'conv-4', sourceUuid: 'me-uuid', timestamp: Date.now() - 86_500_000, type: 2, body: 'Got it, thanks!', isRead: true, sendState: 2 },
    { id: 32, guid: 'msg-4c', conversationId: 'conv-4', sourceUuid: 'team-uuid', timestamp: Date.now() - 86_400_000, type: 1, body: 'Meeting at 3pm tomorrow', isRead: true, sendState: 2 },
  ],
};

const contacts = [
  { uuid: 'alice-uuid', e164: '+15555550101', givenName: 'Alice', familyName: 'Smith', isBlocked: false },
  { uuid: 'bob-uuid', e164: '+15555550102', givenName: 'Bob', familyName: 'Jones', isBlocked: false },
  { uuid: 'charlie-uuid', e164: '+15555550103', givenName: 'Charlie', familyName: 'Davis', isBlocked: false },
  { uuid: 'team-uuid', e164: '+15555550104', givenName: 'Team', familyName: 'Engineering', isBlocked: false },
];

let nextMsgId = 100;

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  // --- Account ---
  if (path === '/api/v1/account/registered' && method === 'GET') {
    return json(res, registered);
  }

  if (path === '/api/v1/account/verify/session' && method === 'POST') {
    return json(res, { id: sessionId });
  }

  if (path === '/api/v1/account/verify/code' && method === 'POST') {
    return json(res, {});
  }

  if (path === '/api/v1/account/verify/submit' && method === 'POST') {
    return json(res, { id: sessionId, verified: true });
  }

  if (path === '/api/v1/account/register' && method === 'POST') {
    registered = true;
    return json(res, { number: '+15555550100', uuid: 'me-uuid', deviceId: 1 });
  }

  if (path === '/api/v1/account/whoami' && method === 'GET') {
    if (!registered) return json(res, { error: 'not registered' }, 401);
    return json(res, { number: '+15555550100', uuid: 'me-uuid', deviceId: 1 });
  }

  // --- Conversations ---
  if (path === '/api/v1/conversations' && method === 'GET') {
    return json(res, conversations);
  }

  // --- Messages ---
  if (path === '/api/v1/messages' && method === 'GET') {
    const convId = url.searchParams.get('conversationId');
    const msgs = messagesByConv[convId] || [];
    return json(res, msgs);
  }

  if (path === '/api/v1/messages/send' && method === 'POST') {
    const body = await readBody(req);
    const newMsg = {
      id: nextMsgId++,
      guid: `msg-${nextMsgId}`,
      conversationId: body.recipient,
      sourceUuid: 'me-uuid',
      timestamp: Date.now(),
      type: 2,
      body: body.text,
      isRead: true,
      sendState: 2,
    };
    if (messagesByConv[body.recipient]) {
      messagesByConv[body.recipient].push(newMsg);
    }
    return json(res, { timestamp: Date.now(), needsSync: false });
  }

  // --- Contacts ---
  if (path === '/api/v1/contacts' && method === 'GET') {
    return json(res, contacts);
  }

  // --- WebSocket events (upgrade) ---
  if (path === '/api/v1/events') {
    // For the mock, just keep the connection alive without actual WS.
    // The browser will see this as a connection.
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('events endpoint - mock');
    return;
  }

  // Fallback
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found', path }));
});

server.listen(PORT, () => {
  console.log(`Mock API server running on http://localhost:${PORT}`);
});
