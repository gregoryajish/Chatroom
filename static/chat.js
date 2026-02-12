var socket = io();

// ---------------- JOIN CURRENT ROOM ON PAGE LOAD ----------------
var roomField = document.getElementById("room_id");
var currentRoomId = roomField ? roomField.value : 1;
socket.emit('join', { room: currentRoomId });

// ---------------- PROFILE POPUP FUNCTIONS (GLOBAL SCOPE) ----------------

let currentProfileUsername = null;

// Open profile modal when clicking on avatar
window.openProfileModal = function (username) {
    console.log('Opening profile for:', username); // Debug log
    currentProfileUsername = username;

    // Set profile info
    document.getElementById('profileAvatar').textContent = username.charAt(0).toUpperCase();
    document.getElementById('profileUsername').textContent = username;
    document.getElementById('profileMessage').textContent = '';
    document.getElementById('profileMessage').className = 'profile-message';

    // Show modal
    document.getElementById('profileModal').classList.add('show');
}

// Close profile modal
window.closeProfileModal = function () {
    console.log('Closing profile modal'); // Debug log
    document.getElementById('profileModal').classList.remove('show');
    currentProfileUsername = null;
}

// Send friend request from profile popup
window.sendFriendRequestFromProfile = function () {
    if (!currentProfileUsername) return;

    console.log('Sending friend request to:', currentProfileUsername); // Debug log
    const messageDiv = document.getElementById('profileMessage');
    messageDiv.textContent = 'Sending...';
    messageDiv.className = 'profile-message';

    // Send AJAX request
    fetch('/api/send_request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: currentProfileUsername
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                messageDiv.textContent = data.message;
                messageDiv.className = 'profile-message success';

                // Auto-close after 2 seconds
                setTimeout(() => {
                    closeProfileModal();
                }, 2000);
            } else {
                messageDiv.textContent = data.message;
                messageDiv.className = 'profile-message error';
            }
        })
        .catch(error => {
            console.error('Error sending friend request:', error);
            messageDiv.textContent = 'Error sending request';
            messageDiv.className = 'profile-message error';
        });
}

// Close modal when clicking outside
window.onclick = function (event) {
    const modal = document.getElementById('profileModal');
    if (event.target === modal) {
        closeProfileModal();
    }
}

// ---------------- SEND MESSAGE ----------------
function sendMessage() {

    var messageInput = document.getElementById("message");
    var message = messageInput.value.trim();

    if (message === "") return;

    // Get room_id (public room = 1, private rooms = other ids)
    var roomField = document.getElementById("room_id");
    var room_id = roomField ? roomField.value : 1;

    socket.emit('send_message', {
        room_id: room_id,
        message: message
    });

    messageInput.value = "";
}

// Allow Enter key to send message
document.addEventListener('DOMContentLoaded', function () {
    var messageInput = document.getElementById("message");
    if (messageInput) {
        messageInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }

    // Attach click handlers to all existing message avatars
    initializeAvatarClickHandlers();
});

// Initialize click handlers for existing avatars
function initializeAvatarClickHandlers() {
    console.log('Initializing avatar click handlers...'); // Debug log
    var avatars = document.querySelectorAll('.message-avatar[data-username]');
    console.log('Found', avatars.length, 'avatars'); // Debug log

    avatars.forEach(function (avatar) {
        var username = avatar.getAttribute('data-username');
        avatar.style.cursor = 'pointer';
        avatar.addEventListener('click', function () {
            console.log('Existing avatar clicked for:', username); // Debug log
            window.openProfileModal(username);
        });
    });
}


// ---------------- RECEIVE MESSAGE ----------------
socket.on('receive_message', function (data) {

    var chatBox = document.getElementById("chat-box");

    // Determine if message is from current user
    var isSentByMe = (data.username === currentUsername);

    // Create message container
    var messageDiv = document.createElement('div');
    messageDiv.className = isSentByMe ? 'message message-sent' : 'message message-received';

    // Create avatar (clickable) - only for received messages or sent messages on right
    var avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.style.cursor = 'pointer';
    avatar.setAttribute('data-username', data.username);

    // Display profile picture or letter avatar
    if (data.profile_picture) {
        var img = document.createElement('img');
        img.src = '/static/uploads/profiles/' + data.profile_picture;
        img.alt = data.username;
        avatar.appendChild(img);
    } else {
        avatar.textContent = data.username.charAt(0).toUpperCase();
    }

    avatar.addEventListener('click', function () {
        console.log('Avatar clicked for:', data.username);
        window.openProfileModal(data.username);
    });

    // Create message content wrapper
    var contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';

    // Create message header
    var headerDiv = document.createElement('div');
    headerDiv.className = 'message-header';

    var authorSpan = document.createElement('span');
    authorSpan.className = 'message-author';
    authorSpan.textContent = data.username;

    headerDiv.appendChild(authorSpan);

    // Create message bubble
    var bubbleDiv = document.createElement('div');
    bubbleDiv.className = 'message-bubble';
    bubbleDiv.textContent = data.message;

    // Assemble message
    contentDiv.appendChild(headerDiv);
    contentDiv.appendChild(bubbleDiv);

    // Add avatar on left for received, right for sent
    if (!isSentByMe) {
        messageDiv.appendChild(avatar);
    }
    messageDiv.appendChild(contentDiv);
    if (isSentByMe) {
        messageDiv.appendChild(avatar);
    }

    chatBox.appendChild(messageDiv);

    chatBox.scrollTop = chatBox.scrollHeight;  // auto scroll
});
