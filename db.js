require('dotenv').config();
const { Pool } = require('pg');

// إعداد الاتصال
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // مطلوب للاتصال بـ Neon
  }
});

// تعريف الدالة التي يطلبها ملف server.js
const connectDB = async () => {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('✅ تم الاتصال بـ Neon PostgreSQL بنجاح في: ' + res.rows[0].now);
  } catch (err) {
    console.error('❌ خطأ في الاتصال بقاعدة البيانات:', err.message);
    process.exit(1);
  }
};

// *** الهام جداً: تصدير الدالة والكائن ***
module.exports = { pool, connectDB };