document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // النجاح: الانتقال للرابط المرسل من السيرفر
            window.location.href = data.redirectUrl;
        } else {
            // فشل: عرض رسالة الخطأ القادمة من السيرفر
            messageDiv.textContent = data.message;
        }
    } catch (error) {
        console.error('Login Error:', error);
        messageDiv.textContent = 'تعذر الاتصال بالسيرفر، حاول لاحقاً.';
    }
});