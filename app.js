// ZeroLink Client Application Logic

// ==========================================
// 1. STATE MANAGEMENT
// ==========================================
const state = {
  profile: { name: 'Anonymous' },
  connections: {},       // contactId -> { name, inQueue, outQueue, sharedKeyHex, keyData }
  messages: {},          // contactId -> array of { sender, text, timestamp, decrypted }
  activeContactId: null,
  activeInvitation: null, // { inboundQueueId, keyPair }
  activeSSE: {}          // contactId -> EventSource
};

const DOM = {
  profileNameInput: document.getElementById('profile-name'),
  saveProfileBtn: document.getElementById('save-profile-btn'),
  connectionsList: document.getElementById('connections-list'),
  chatEmptyState: document.getElementById('chat-empty-state'),
  chatInterface: document.getElementById('chat-interface'),
  chatContactName: document.getElementById('chat-contact-name'),
  chatAvatar: document.getElementById('chat-avatar'),
  messagePane: document.getElementById('message-pane'),
  messageForm: document.getElementById('message-form'),
  messageInput: document.getElementById('message-input'),
  showAddConnModal: document.getElementById('show-add-conn-modal'),
  showInviteBtnWelcome: document.getElementById('show-invite-btn-welcome'),
  closeModalBtn: document.getElementById('close-modal-btn'),
  connectionModal: document.getElementById('connection-modal'),
  generateInviteBtn: document.getElementById('generate-invite-btn'),
  inviteResultBox: document.getElementById('invite-result-box'),
  inviteLinkInput: document.getElementById('invite-link-input'),
  copyInviteBtn: document.getElementById('copy-invite-btn'),
  acceptLinkInput: document.getElementById('accept-link-input'),
  acceptContactName: document.getElementById('accept-contact-name'),
  connectBtn: document.getElementById('connect-btn'),
  consoleLogs: document.getElementById('console-logs'),
  cryptoWarning: document.getElementById('crypto-warning'),
  vizSharedKey: document.getElementById('viz-shared-key'),
  vizOutQueue: document.getElementById('viz-out-queue'),
  vizInQueue: document.getElementById('viz-in-queue'),
  vizQ1Id: document.getElementById('viz-q1-id'),
  vizQ2Id: document.getElementById('viz-q2-id'),
  vizContactName: document.getElementById('viz-contact-name'),
  visualizerSvg: document.getElementById('visualizer-svg')
};

// ==========================================
// 2. CRYPTOGRAPHIC WRAPPER (WebCrypto)
// ==========================================
const CryptoHelper = {
  // Generate ECDH Keypair for handshake
  async generateDHKeyPair() {
    return await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  },

  // Export public key to SPKI Base64 format
  async exportPublicKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(exported);
  },

  // Import public key from SPKI Base64 format
  async importPublicKey(spkiBase64) {
    const binary = base64ToArrayBuffer(spkiBase64);
    return await window.crypto.subtle.importKey(
      'spki',
      binary,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  },

  // Derive shared AES-GCM symmetric key
  async deriveAESKey(privateKey, publicKey) {
    const sharedSecret = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: publicKey },
      privateKey,
      256
    );
    
    // Import raw bytes as AES-GCM key
    return await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Helper to convert derived AES-GCM key back to hex for visualization
  async exportAESKeyToHex(aesKey) {
    const raw = await window.crypto.subtle.exportKey('raw', aesKey);
    const bytes = new Uint8Array(raw);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Encrypt string with AES-GCM
  async encrypt(plaintext, aesKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encoder.encode(plaintext)
    );
    return JSON.stringify({
      iv: arrayBufferToBase64(iv),
      ct: arrayBufferToBase64(ciphertext)
    });
  },

  // Decrypt ciphertext JSON string with AES-GCM
  async decrypt(cipherJson, aesKey) {
    try {
      const { iv, ct } = JSON.parse(cipherJson);
      const ivBuffer = new Uint8Array(base64ToArrayBuffer(iv));
      const ctBuffer = base64ToArrayBuffer(ct);
      
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: ivBuffer },
        aesKey,
        ctBuffer
      );
      
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (e) {
      console.error("Decryption failed:", e);
      return "[Decryption Failed: Keys mismatch or corrupted payload]";
    }
  }
};

// Encoding helpers
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// ==========================================
// 3. UI CONSOLE LOGGING REPRESENTATION
// ==========================================
function addConsoleLog(text, type = 'system') {
  const line = document.createElement('div');
  line.className = `console-line ${type}`;
  const timestamp = new Date().toLocaleTimeString();
  line.innerText = `[${timestamp}] ${text}`;
  DOM.consoleLogs.appendChild(line);
  DOM.consoleLogs.scrollTop = DOM.consoleLogs.scrollHeight;
}

// ==========================================
// 4. STORAGE & INITIALIZATION
// ==========================================
function loadFromStorage() {
  const savedProfile = localStorage.getItem('cc_profile');
  if (savedProfile) {
    state.profile = JSON.parse(savedProfile);
    DOM.profileNameInput.value = state.profile.name;
  } else {
    state.profile = { name: 'User_' + Math.floor(Math.random() * 9000 + 1000) };
    DOM.profileNameInput.value = state.profile.name;
    localStorage.setItem('cc_profile', JSON.stringify(state.profile));
  }

  const savedConnections = localStorage.getItem('cc_connections');
  if (savedConnections) {
    state.connections = JSON.parse(savedConnections);
  }

  const savedMessages = localStorage.getItem('cc_messages');
  if (savedMessages) {
    state.messages = JSON.parse(savedMessages);
  }
}

async function init() {
  // Check secure context / WebCrypto availability
  if (!window.crypto || !window.crypto.subtle) {
    DOM.cryptoWarning.classList.remove('hidden');
    addConsoleLog("CRITICAL: WebCrypto API not available. Use localhost or HTTPS.", "system");
  }

  loadFromStorage();
  renderConnections();
  addConsoleLog("Local identity loaded: " + state.profile.name, "system");
  initMobileNavigation();

  // Re-establish streams for existing connections
  for (const connId of Object.keys(state.connections)) {
    subscribeToQueue(connId);
  }
}

// ==========================================
// 5. QUEUE NETWORKING & HANDSHAKE
// ==========================================
const API_BASE = window.location.origin;

async function createQueue() {
  try {
    const res = await fetch(`${API_BASE}/api/queue/create`, { method: 'POST' });
    if (!res.ok) {
      throw new Error(`HTTP Error: ${res.status} ${res.statusText}`);
    }
    const data = await res.json();
    if (!data.queueId) {
      throw new Error("Invalid response: queueId is missing");
    }
    return data.queueId;
  } catch (e) {
    throw new Error(`Network/Server Error: ${e.message || e}`);
  }
}

async function sendMessageToQueue(queueId, payload, serverUrl = API_BASE) {
  const res = await fetch(`${serverUrl}/api/queue/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queueId, payload })
  });
  return await res.json();
}

async function acknowledgeMessage(queueId, messageId) {
  await fetch(`${API_BASE}/api/queue/ack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queueId, messageId })
  });
}

// Generate Handshake invitation
async function generateInvitation() {
  try {
    addConsoleLog("Generating ephemeral handshake DH keypair...", "system");
    const keyPair = await CryptoHelper.generateDHKeyPair();
    
    addConsoleLog("Exporting public key...", "system");
    const pubKeyBase64 = await CryptoHelper.exportPublicKey(keyPair.publicKey);
    
    addConsoleLog("Requesting inbound queue from server...", "system");
    const inboundQueueId = await createQueue();

    state.activeInvitation = { inboundQueueId, keyPair };

    const inviteData = {
      server: API_BASE,
      queueId: inboundQueueId,
      pubKey: pubKeyBase64,
      senderName: state.profile.name
    };

    const inviteString = 'zerolink://invite/' + window.btoa(JSON.stringify(inviteData));
    DOM.inviteLinkInput.value = inviteString;
    DOM.inviteResultBox.classList.remove('hidden');

    addConsoleLog(`Inbound queue created: ${inboundQueueId.slice(0,8)}...`, "in");
    addConsoleLog("Awaiting connection handshake response...", "system");

    // Subscribe to inbound queue to await handshake reply
    subscribeToHandshakeQueue(inboundQueueId, keyPair);
  } catch (err) {
    const errMsg = err.message || err;
    addConsoleLog(`CRITICAL ERROR during invite generation: ${errMsg}`, "system");
    console.error("Invite generation failed:", err);
    alert("CRITICAL ERROR during invite generation:\n" + errMsg);
  }
}

// Alice waits for Bob to write handshake to her inbound queue
function subscribeToHandshakeQueue(queueId, aliceKeyPair) {
  const eventSource = new EventSource(`${API_BASE}/api/queue/events/${queueId}`);

  eventSource.onmessage = async (event) => {
    try {
      const message = JSON.parse(event.data);
      const data = JSON.parse(message.payload);

      // We expect Bob's handshake response structure:
      // { pubKey: 'spkiBase64Key', encryptedPayload: 'JSON' }
      if (data.pubKey && data.encryptedPayload) {
        addConsoleLog("Received handshake response on invite queue!", "in");
        
        eventSource.close(); // Handshake queue job is done

        // Import Bob's public key
        const bobPubKey = await CryptoHelper.importPublicKey(data.pubKey);
        // Derive shared AES key
        const sharedKey = await CryptoHelper.deriveAESKey(aliceKeyPair.privateKey, bobPubKey);
        const sharedKeyHex = await CryptoHelper.exportAESKeyToHex(sharedKey);

        // Decrypt Bob's details
        const decryptedPayload = await CryptoHelper.decrypt(data.encryptedPayload, sharedKey);
        const bobDetails = JSON.parse(decryptedPayload);

        // Save connection
        const contactId = uuid();
        const connection = {
          id: contactId,
          name: bobDetails.name || "Contact",
          inQueue: queueId,       // Alice receives here (Alice's server)
          outQueue: bobDetails.queueId,  // Alice sends here (Bob's server)
          outServer: bobDetails.server || API_BASE, // Bob's server URL
          sharedKeyHex: sharedKeyHex
        };

        // Save connection locally
        state.connections[contactId] = connection;
        localStorage.setItem('cc_connections', JSON.stringify(state.connections));
        
        // Export key to local session storage (we don't persist CryptoKey objects directly in localstorage)
        sessionStorage.setItem(`cc_key_${contactId}`, JSON.stringify(await serializeKey(sharedKey)));

        addConsoleLog(`Handshake completed! Connection established with ${connection.name}`, "system");
        addConsoleLog(`Shared symmetric key derived: ${sharedKeyHex.slice(0, 16)}...`, "system");

        // Send confirmation handshake reply to Bob's inbound queue
        const confirmation = { handshakeConfirm: true, name: state.profile.name };
        const encConfirmation = await CryptoHelper.encrypt(JSON.stringify(confirmation), sharedKey);
        await sendMessageToQueue(connection.outQueue, encConfirmation, connection.outServer);

        // Ack & Clean message on server
        await acknowledgeMessage(queueId, message.id);

        renderConnections();
        subscribeToQueue(contactId);

        // Automatically open the new chat
        selectContact(contactId);

        // Close modal
        closeModal();
      }
    } catch (e) {
      console.error("Handshake processing failed:", e);
    }
  };
}

// Bob accepts Alice's invitation
async function acceptInvitation(inviteUrl, contactAlias) {
  try {
    const rawInvite = inviteUrl.replace('zerolink://invite/', '');
    const inviteData = JSON.parse(window.atob(rawInvite));
    
    addConsoleLog(`Accepting invitation from ${inviteData.senderName}...`, "system");

    // 1. Generate Bob's keypair
    const bobKeyPair = await CryptoHelper.generateDHKeyPair();
    const bobPubKeyBase64 = await CryptoHelper.exportPublicKey(bobKeyPair.publicKey);

    // 2. Create Bob's inbound queue
    const bobInboundQueue = await createQueue();
    addConsoleLog(`Inbound queue created: ${bobInboundQueue.slice(0,8)}...`, "in");

    // 3. Derive shared AES key from Alice's public key
    const alicePubKey = await CryptoHelper.importPublicKey(inviteData.pubKey);
    const sharedKey = await CryptoHelper.deriveAESKey(bobKeyPair.privateKey, alicePubKey);
    const sharedKeyHex = await CryptoHelper.exportAESKeyToHex(sharedKey);

    // 4. Encrypt Bob's details for Alice
    const myDetails = { 
      queueId: bobInboundQueue, 
      server: API_BASE, // Share Bob's server URL with Alice
      name: state.profile.name 
    };
    const encDetails = await CryptoHelper.encrypt(JSON.stringify(myDetails), sharedKey);

    // 5. Send handshake response to Alice's inbound queue
    const handshakeResponse = {
      pubKey: bobPubKeyBase64,
      encryptedPayload: encDetails
    };

    addConsoleLog(`Sending handshake reply to contact's invite queue on ${inviteData.server}...`, "out");
    await sendMessageToQueue(inviteData.queueId, JSON.stringify(handshakeResponse), inviteData.server);

    // 6. Save connection
    const contactId = uuid();
    const connection = {
      id: contactId,
      name: contactAlias || inviteData.senderName || "Contact",
      inQueue: bobInboundQueue,      // Bob receives here (Bob's server)
      outQueue: inviteData.queueId,  // Bob sends here (Alice's server)
      outServer: inviteData.server,  // Alice's server URL
      sharedKeyHex: sharedKeyHex
    };

    state.connections[contactId] = connection;
    localStorage.setItem('cc_connections', JSON.stringify(state.connections));
    sessionStorage.setItem(`cc_key_${contactId}`, JSON.stringify(await serializeKey(sharedKey)));

    renderConnections();
    subscribeToQueue(contactId);

    addConsoleLog(`Handshake completed! Connection established with ${connection.name}`, "system");

    // Open chat
    selectContact(contactId);
    closeModal();

  } catch (e) {
    alert("Invalid invitation link structure.");
    console.error("Accepting invitation failed:", e);
  }
}

// Subscribe to contact communication queue for real-time messages
function subscribeToQueue(contactId) {
  // Avoid duplicate subscriptions
  if (state.activeSSE[contactId]) {
    state.activeSSE[contactId].close();
  }

  const conn = state.connections[contactId];
  const eventSource = new EventSource(`${API_BASE}/api/queue/events/${conn.inQueue}`);
  state.activeSSE[contactId] = eventSource;

  eventSource.onmessage = async (event) => {
    try {
      const message = JSON.parse(event.data);
      const aesKey = await getOrLoadKey(contactId);

      if (!aesKey) {
        addConsoleLog(`Error: AES Key missing for connection ${conn.name}. Cannot decrypt!`, "system");
        return;
      }

      // Decrypt message payload
      const decryptedText = await CryptoHelper.decrypt(message.payload, aesKey);

      // Check if handshake confirmation message
      if (decryptedText.includes("handshakeConfirm")) {
        addConsoleLog(`Verified handshake confirmation from ${conn.name}`, "system");
        await acknowledgeMessage(conn.inQueue, message.id);
        return;
      }

      addConsoleLog(`Received encrypted message on Queue: ${conn.inQueue.slice(0,8)}...`, "in");
      triggerPacketAnimation('packet-q2'); // Receive path animation

      // Push message to local history
      if (!state.messages[contactId]) {
        state.messages[contactId] = [];
      }
      
      // Avoid duplicate push (on reconnection sync)
      if (!state.messages[contactId].some(m => m.id === message.id)) {
        state.messages[contactId].push({
          id: message.id,
          sender: conn.name,
          text: decryptedText,
          timestamp: message.timestamp,
          decrypted: true
        });
        localStorage.setItem('cc_messages', JSON.stringify(state.messages));
      }

      // Ack received message to delete it from server
      await acknowledgeMessage(conn.inQueue, message.id);

      // Render if active
      if (state.activeContactId === contactId) {
        renderMessages(contactId);
      }

    } catch (e) {
      console.error("Error receiving queue message:", e);
    }
  };
}

// ==========================================
// 6. CRYPTOKEY SERIALIZATION
// ==========================================
// Serializes Key to JSON to store in sessionStorage
async function serializeKey(key) {
  const raw = await window.crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(raw);
}

// Gets key from Memory or SessionStorage
async function getOrLoadKey(contactId) {
  const b64 = sessionStorage.getItem(`cc_key_${contactId}`);
  if (!b64) return null;
  const raw = base64ToArrayBuffer(JSON.parse(b64));
  return await window.crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ==========================================
// 7. CHAT & MESSAGE SENDING
// ==========================================
async function sendMessage(text) {
  if (!state.activeContactId) return;
  const contactId = state.activeContactId;
  const conn = state.connections[contactId];

  addConsoleLog(`Encrypting message for ${conn.name}...`, "system");
  const aesKey = await getOrLoadKey(contactId);
  const encryptedPayload = await CryptoHelper.encrypt(text, aesKey);

  addConsoleLog(`Pushing payload to Queue: ${conn.outQueue.slice(0,8)}...`, "out");
  triggerPacketAnimation('packet-q1'); // Send path animation
  addConsoleLog(`Encrypting and sending message to ${conn.name}...`, "out");
  const result = await sendMessageToQueue(conn.outQueue, encryptedPayload, conn.outServer);
  
  if (result.success) {
    if (!state.messages[contactId]) {
      state.messages[contactId] = [];
    }
    state.messages[contactId].push({
      id: result.messageId,
      sender: 'You',
      text: text,
      timestamp: Date.now(),
      decrypted: true
    });
    localStorage.setItem('cc_messages', JSON.stringify(state.messages));
    renderMessages(contactId);
  }
}

// ==========================================
// 8. INTERACTIVE VISUALIZER ANIMATIONS
// ==========================================
function triggerPacketAnimation(packetId) {
  const packet = document.getElementById(packetId);
  const path = document.getElementById(packetId === 'packet-q1' ? 'path-q1-send' : 'path-q2-send');
  if (!packet || !path) return;

  // Add css animation class to SVG to animate dashes
  DOM.visualizerSvg.classList.add('diagram-active');

  const pathLen = path.getTotalLength();
  packet.setAttribute('opacity', '1');

  let start = null;
  const duration = 1200; // ms

  function animate(timestamp) {
    if (!start) start = timestamp;
    const progress = (timestamp - start) / duration;

    if (progress < 1) {
      const point = path.getPointAtLength(progress * pathLen);
      packet.setAttribute('cx', point.x);
      packet.setAttribute('cy', point.y);
      requestAnimationFrame(animate);
    } else {
      packet.setAttribute('opacity', '0');
      // Shift to receiver part of the path
      const recvPath = document.getElementById(packetId === 'packet-q1' ? 'path-q1-recv' : 'path-q2-recv');
      if (recvPath) {
        let rStart = null;
        const rPathLen = recvPath.getTotalLength();
        packet.setAttribute('opacity', '1');
        
        function animateRecv(rTimestamp) {
          if (!rStart) rStart = rTimestamp;
          const rProgress = (rTimestamp - rStart) / duration;
          
          if (rProgress < 1) {
            const point = recvPath.getPointAtLength(rProgress * rPathLen);
            packet.setAttribute('cx', point.x);
            packet.setAttribute('cy', point.y);
            requestAnimationFrame(animateRecv);
          } else {
            packet.setAttribute('opacity', '0');
            DOM.visualizerSvg.classList.remove('diagram-active');
          }
        }
        requestAnimationFrame(animateRecv);
      }
    }
  }
  requestAnimationFrame(animate);
}

function updateVisualizer(conn) {
  if (!conn) {
    DOM.vizSharedKey.innerText = "None (No Active Chat)";
    DOM.vizOutQueue.innerText = "None";
    DOM.vizInQueue.innerText = "None";
    DOM.vizQ1Id.textContent = "Q1: None";
    DOM.vizQ2Id.textContent = "Q2: None";
    DOM.vizContactName.textContent = "Bob";
    return;
  }

  DOM.vizSharedKey.innerText = conn.sharedKeyHex;
  DOM.vizOutQueue.innerText = conn.outQueue;
  DOM.vizInQueue.innerText = conn.inQueue;
  DOM.vizQ1Id.textContent = `Q1: ${conn.outQueue.slice(0, 6)}`;
  DOM.vizQ2Id.textContent = `Q2: ${conn.inQueue.slice(0, 6)}`;
  DOM.vizContactName.textContent = conn.name;
}

// ==========================================
// 9. DOM RENDERING
// ==========================================
function renderConnections() {
  DOM.connectionsList.innerHTML = '';
  const connIds = Object.keys(state.connections);

  if (connIds.length === 0) {
    DOM.connectionsList.innerHTML = '<div class="empty-state">No secure connections yet. Add one to start.</div>';
    return;
  }

  connIds.forEach(id => {
    const conn = state.connections[id];
    const item = document.createElement('div');
    item.className = `connection-item ${state.activeContactId === id ? 'active' : ''}`;
    
    // Initial letter avatar
    const letter = conn.name.charAt(0).toUpperCase();

    item.innerHTML = `
      <div class="avatar">${letter}</div>
      <div class="connection-info">
        <div class="connection-name">${conn.name}</div>
        <div class="connection-queue-desc">Out: ${conn.outQueue.slice(0, 6)}... | In: ${conn.inQueue.slice(0, 6)}...</div>
      </div>
      <button class="delete-conn-btn" title="Delete connection">&times;</button>
    `;

    item.addEventListener('click', () => selectContact(id));
    
    const delBtn = item.querySelector('.delete-conn-btn');
    delBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteConnection(id);
    });
    
    DOM.connectionsList.appendChild(item);
  });
}

function deleteConnection(id) {
  if (!confirm("Are you sure you want to delete this secure connection? All message history and keys will be permanently lost.")) return;
  
  // Close SSE stream
  if (state.activeSSE[id]) {
    state.activeSSE[id].close();
    delete state.activeSSE[id];
  }
  
  // Remove data
  delete state.connections[id];
  delete state.messages[id];
  localStorage.setItem('cc_connections', JSON.stringify(state.connections));
  localStorage.setItem('cc_messages', JSON.stringify(state.messages));
  sessionStorage.removeItem(`cc_key_${id}`);
  
  // Reset view if active
  if (state.activeContactId === id) {
    state.activeContactId = null;
    DOM.chatEmptyState.classList.remove('hidden');
    DOM.chatInterface.classList.add('hidden');
    updateVisualizer(null);
  }
  
  addConsoleLog("Connection deleted and keys purged.", "system");
  renderConnections();
}

function selectContact(id) {
  state.activeContactId = id;
  const conn = state.connections[id];
  
  // Update header UI
  DOM.chatContactName.innerText = conn.name;
  DOM.chatAvatar.innerText = conn.name.charAt(0).toUpperCase();
  
  DOM.chatEmptyState.classList.add('hidden');
  DOM.chatInterface.classList.remove('hidden');
  
  // Highlight active sidebar item
  renderConnections();
  
  // Render messages
  renderMessages(id);
  
  // Update Visualizer
  updateVisualizer(conn);

  // On mobile, show back button and switch to chats tab
  document.body.classList.add('show-back-btn');
  const chatsTab = document.querySelector('.nav-tab[data-target="chats"]');
  if (chatsTab) chatsTab.click();

  addConsoleLog(`Inspecting connection parameters with ${conn.name}...`, "system");
}

function renderMessages(contactId) {
  DOM.messagePane.innerHTML = '';
  const history = state.messages[contactId] || [];

  if (history.length === 0) {
    DOM.messagePane.innerHTML = '<div class="empty-state">No messages in this chat. Send a message to begin.</div>';
    return;
  }

  history.forEach(msg => {
    const row = document.createElement('div');
    const isMe = msg.sender === 'You';
    row.className = `message-row ${isMe ? 'sent' : 'received'}`;

    const date = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    row.innerHTML = `
      <div class="message-bubble">
        <div class="message-text">${escapeHTML(msg.text)}</div>
        <div class="message-meta">
          ${isMe ? '' : '<span class="crypto-meta-tag">AES-GCM-256</span>'}
          <span class="message-time">${date}</span>
        </div>
      </div>
    `;

    DOM.messagePane.appendChild(row);
  });

  DOM.messagePane.scrollTop = DOM.messagePane.scrollHeight;
}

function escapeHTML(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}

// ==========================================
// 10. MODAL & TAB CONTROLS
// ==========================================
function openModal() {
  DOM.connectionModal.classList.remove('hidden');
  resetModal();
}

function closeModal() {
  DOM.connectionModal.classList.add('hidden');
}

function resetModal() {
  DOM.inviteResultBox.classList.add('hidden');
  DOM.inviteLinkInput.value = '';
  DOM.acceptLinkInput.value = '';
  DOM.acceptContactName.value = '';
}

// ==========================================
// 11. EVENT LISTENERS
// ==========================================
DOM.showAddConnModal.addEventListener('click', openModal);
DOM.showInviteBtnWelcome.addEventListener('click', openModal);
DOM.closeModalBtn.addEventListener('click', closeModal);

// Profile Name set
DOM.saveProfileBtn.addEventListener('click', () => {
  const newName = DOM.profileNameInput.value.trim();
  if (newName) {
    state.profile.name = newName;
    localStorage.setItem('cc_profile', JSON.stringify(state.profile));
    addConsoleLog("Local alias updated: " + newName, "system");
    alert("Profile name updated locally!");
  }
});

// Modal Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
  });
});

// Generate Invitation Link
DOM.generateInviteBtn.addEventListener('click', generateInvitation);

// Copy Invitation Link
DOM.copyInviteBtn.addEventListener('click', () => {
  DOM.inviteLinkInput.select();
  document.execCommand('copy');
  addConsoleLog("Invitation link copied to clipboard.", "system");
  alert("Link copied to clipboard!");
});

// Accept Invitation Link
DOM.connectBtn.addEventListener('click', () => {
  const inviteLink = DOM.acceptLinkInput.value.trim();
  const contactName = DOM.acceptContactName.value.trim();

  if (!inviteLink) {
    alert("Please paste an invitation link.");
    return;
  }
  if (!contactName) {
    alert("Please enter a local nickname for this contact.");
    return;
  }

  acceptInvitation(inviteLink, contactName);
});

// Chat Send Form
DOM.messageForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = DOM.messageInput.value.trim();
  if (!text) return;
  
  sendMessage(text);
  DOM.messageInput.value = '';
});

// Helper UUID generator
function uuid() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

// Window init
window.addEventListener('DOMContentLoaded', init);

// ==========================================
// 12. MOBILE NAVIGATION LOGIC
// ==========================================
function initMobileNavigation() {
  document.body.classList.add('mobile-tab-chats');
  
  const navTabs = document.querySelectorAll('.nav-tab');
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove all mobile-tab-* classes from body
      document.body.className = document.body.className.replace(/mobile-tab-\w+/g, '').trim();
      // Add the new one
      document.body.classList.add(`mobile-tab-${tab.dataset.target}`);
      
      // Update active state on tabs
      navTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
    });
  });

  const mobileBackBtn = document.getElementById('mobile-back-btn');
  if (mobileBackBtn) {
    mobileBackBtn.addEventListener('click', () => {
      document.body.classList.remove('show-back-btn');
      // Go back to connections tab
      const connTab = document.querySelector('.nav-tab[data-target="connections"]');
      if (connTab) connTab.click();
      
      // Clear active contact view
      state.activeContactId = null;
      DOM.chatEmptyState.classList.remove('hidden');
      DOM.chatInterface.classList.add('hidden');
      renderConnections();
    });
  }
}
