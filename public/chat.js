// this are the event listnears used 

document.addEventListener('DOMContentLoaded', () => {
    const sendButton = document.getElementById('send-button');
    const userInput = document.getElementById('user-input');
    const messageInput = document.getElementById('message-input');
    const messagesList = document.getElementById('messages-list');
    const loginButton = document.getElementById('login-button');
    const usernameInput = document.getElementById('username-input');
    const passwordInput = document.getElementById('password-input');
    const registerButton = document.getElementById('register-button');
    const registrationUsernameInput = document.getElementById('registration-username-input');
    const registrationPasswordInput = document.getElementById('registration-password-input');
    const logoutButton = document.getElementById('logout-button'); // Add reference to logout button

    let token = localStorage.getItem('token');// here we are storing token in local sstorage

    // Check if elements exist
    if (!sendButton || !userInput || !messageInput || !messagesList || !loginButton || !registerButton || !logoutButton) {
        console.error('One or more elements not found');
        return; 
    }

    // Function to display the messages section and hide login/registration
    function showMessagesSection() {
        document.getElementById('login-container').style.display = 'none';
        document.getElementById('registration-container').style.display = 'none';
        messagesList.style.display = 'block'; // Show messages list
        document.querySelector('.chat-input').style.display = 'flex'; // Show chat input
        fetchMessages(); // Fetch messages after displaying
    }

    // Function to handle login
    async function login() {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();

        if (validateInputs(username, password)) {
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password }),
                });

                const data = await response.json();

                if (response.ok) {
                    token = data.token;
                    localStorage.setItem('token', token);
                    alert('Login successful');
                    showMessagesSection(); // Show messages after successful login
                } else {
                    alert('Login failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error during login:', error);
            }
        }
    }

    // Function to handle registration
    async function register() {
        const username = registrationUsernameInput.value.trim();
        const password = registrationPasswordInput.value.trim();

        if (validateInputs(username, password)) {
            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password }),
                });

                const data = await response.json();

                if (response.ok) {
                    alert('Registration successful. Please log in.');
                    // Reset view to login after successful registration
                    document.getElementById('registration-container').style.display = 'none';
                    document.getElementById('login-container').style.display = 'flex';
                } else {
                    alert('Registration failed: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error during registration:', error);
            }
        }
    }

    // Input validation function
    function validateInputs(username, password) {
        if (!username || !password) {
            alert('Username and password cannot be empty');
            return false;
        }
        return true;
    }

    // Function to fetch messages from the server
    async function fetchMessages() {
        if (!token) {
            alert('You need to log in first');
            return;
        }

        try {
            const response = await fetch('/messages', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`, // Send JWT token in header
                },
            });

            if (response.status === 401) {
                alert('Session expired. Please log in again.');
                localStorage.removeItem('token');
                token = null;
                resetView(); // Reset view to login
                return;
            }

            const data = await response.json();
            messagesList.innerHTML = data.map(msg => 
                `<li class="${msg.user === usernameInput.value.trim() ? 'sent' : 'received'}">
                    <span><strong>${msg.user}:</strong> ${msg.message}</span>
                    <button class="delete-btn" data-id="${msg._id}">Delete</button>
                </li>`
            ).join('');

            // Add event listeners to delete buttons
            document.querySelectorAll('.delete-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const messageId = event.target.getAttribute('data-id');
                    await deleteMessage(messageId);
                    fetchMessages(); // Refresh messages after deletion
                });
            });
        } catch (error) {
            console.error('Error fetching messages:', error);
        }
    }

    // Function to send a new message
    async function sendMessage() {
        if (!token) {
            alert('You need to log in first');
            return;
        }

        const user = usernameInput.value.trim(); // Use the logged-in username
        const message = messageInput.value.trim();

        if (!message) {
            alert('Message cannot be empty');
            return;
        }

        try {
            const response = await fetch('/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`, // Send JWT token in header
                },
                body: JSON.stringify({ user, message }),
            });

            const data = await response.json();

            if (response.ok) {
                messageInput.value = ''; // Clear the message input field
                fetchMessages(); // Refresh messages after sending
            } else {
                alert('Failed to send message: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Error sending message:', error);
        }
    }

    // Function to delete a message
    async function deleteMessage(messageId) {
        if (!token) {
            alert('You need to log in first');
            return;
        }

        try {
            await fetch(`/messages/${messageId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`, // Send JWT token in header
                },
            });
        } catch (error) {
            console.error('Error deleting message:', error);
        }
    }

    // Function to reset view to login
    function resetView() {
        document.getElementById('login-container').style.display = 'flex';
        document.getElementById('registration-container').style.display = 'flex';
        messagesList.style.display = 'none'; // Hide messages
        document.querySelector('.chat-input').style.display = 'none'; // Hide chat input
    }

    // Function to handle logout
    function logout() {
        localStorage.removeItem('token'); // Remove token from local storage
        token = null; // Clear token variable
        resetView(); // Reset view to login
        alert('You have logged out successfully.');
    }

    // Event listeners for buttons
    sendButton.addEventListener('click', sendMessage);
    loginButton.addEventListener('click', login);
    registerButton.addEventListener('click', register);
    logoutButton.addEventListener('click', logout); // Add event listener for logout button

    // Initial fetch of messages after login
    if (token) {
        showMessagesSection(); // Show messages section if already logged in
    }

    // Optionally, use Socket.IO for real-time messaging
    const socket = io(); // Initialize Socket.IO client
    socket.on('newMessage', (message) => {
        fetchMessages(); // Refresh messages when a new message is received
    });
});
