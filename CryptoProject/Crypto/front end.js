document.addEventListener('DOMContentLoaded', function() {
    const blockchainDiv = document.getElementById('blockchain');
    const transactionForm = document.getElementById('transaction-form');

    // Fetch blockchain data when the page loads
    fetchBlockchainData();

    // Handle form submission to create a new transaction
    transactionForm.addEventListener('submit', function(event) {
        event.preventDefault();
        const sender = document.getElementById('sender').value;
        const recipient = document.getElementById('recipient').value;
        const amount = document.getElementById('amount').value;
        createTransaction(sender, recipient, amount);
    });

    // Function to fetch blockchain data from the server
    async function fetchBlockchainData() {
        try {
            const response = await fetch('/blockchain', {
                headers: {
                    'Authorization': 'Bearer ' + getToken()
                }
            });
            if (!response.ok) {
                throw new Error('Failed to fetch blockchain data');
            }
            const data = await response.json();
            // Update the UI with blockchain data
            blockchainDiv.innerHTML = JSON.stringify(data.chain, null, 2);
        } catch (error) {
            console.error('Error fetching blockchain data:', error);
        }
    }

    // Function to create a new transaction
    async function createTransaction(sender, recipient, amount) {
        try {
            const response = await fetch('/transaction', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + getToken(),
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify({
                    sender: sender,
                    recipient: recipient,
                    amount: amount
                })
            });
            if (!response.ok) {
                throw new Error('Failed to create transaction');
            }
            const data = await response.json();
            // Display success message or handle errors
            console.log('Transaction created:', data);
            fetchBlockchainData(); // Update blockchain data after creating transaction
        } catch (error) {
            console.error('Error creating transaction:', error);
        }
    }

    // Function to retrieve JWT token from local storage
    function getToken() {
        return localStorage.getItem('token');
    }

    // Function to retrieve CSRF token from a secure cookie
    function getCSRFToken() {
        return document.cookie.replace(/(?:(?:^|.*;\s*)csrfToken\s*=\s*([^;]*).*$)|^.*$/, "$1");
    }
});
