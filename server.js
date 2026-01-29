const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const { connectDB, pool } = require('./db'); // تأكد أن ملف db.js موجود

const app = express();
const PORT = process.env.PORT || 3000;

// مفتاح سري متغير لزيادة الأمان (يمكنك تغييره لمفتاح ثابت في .env)
const JWT_SECRET = crypto.randomBytes(64).toString('hex');

// 1. الاتصال بقاعدة البيانات
connectDB();

// 2. إعدادات الأمان والبيانات الأساسية
app.use(helmet({
    contentSecurityPolicy: false, // للسماح بالصور والسكربتات الداخلية
    crossOriginEmbedderPolicy: false
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------------------------------------------------------
// 3. الملفات العامة (Static Files)
// ---------------------------------------------------------

// أ) مجلد الصور (ليظهر للجميع)
app.use('/uploads', express.static(path.join(__dirname, 'front-end', 'user', 'uploads','intro')));

// ب) ملفات المستخدم العادي (CSS, JS, HTML) متاحة للجميع
app.use(express.static(path.join(__dirname, 'front-end', 'user')));

// ---------------------------------------------------------
// 4. إعدادات رفع الصور (Multer)
// ---------------------------------------------------------
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'front-end', 'user', 'uploads');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        // تسمية فريدة للملف لعدم تكرار الأسماء
        cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '-'));
    }
});
const upload = multer({ storage: storage });

// ---------------------------------------------------------
// 5. حماية لوحة التحكم (Admin Middleware)
// ---------------------------------------------------------
const adminAuth = (req, res, next) => {
    const token = req.cookies.admin_token;
    
    // منع حفظ صفحات الأدمن في الكاش للمتصفح
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    if (!token) {
        return res.status(403).send(`
            <div style="text-align:center; margin-top:50px; font-family:sans-serif;">
                <h1>🚫 ممنوع الوصول</h1>
                <p>يجب عليك تسجيل الدخول أولاً.</p>
                <a href="/login">الذهاب لصفحة الدخول</a>
            </div>
        `);
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        if (verified.role !== 'admin') {
            return res.status(403).send("أنت لست مسؤولاً (Admin).");
        }
        req.user = verified;
        next();
    } catch (err) {
        res.clearCookie('admin_token');
        return res.redirect('/login');
    }
};

// تطبيق الحماية على ملفات الأدمن
app.use('/admin', adminAuth, express.static(path.join(__dirname, 'front-end', 'admin')));

// ---------------------------------------------------------
// 6. المسارات الرئيسية (Routes HTML)
// ---------------------------------------------------------

// الصفحة الرئيسية (Intro)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'front-end/user/home-store/home-store.html'));
});

// صفحة الدخول
app.get('/login', (req, res) => {
    if (req.cookies.admin_token) {
        return res.redirect('/admin/home-admin/home-admin.html');
    }
    res.sendFile(path.join(__dirname, 'front-end/user/login/login.html'));
});

// تسجيل الخروج
app.get('/logout', (req, res) => {
    res.clearCookie('admin_token');
    res.redirect('/login');
});

// ---------------------------------------------------------
// 7. API: تسجيل الدخول
// ---------------------------------------------------------
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'بيانات ناقصة' });

    try {
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username.trim()]);
        if (result.rows.length === 0) return res.status(400).json({ success: false, message: 'بيانات خاطئة' });

        const adminUser = result.rows[0];
        const isMatch = await bcrypt.compare(password, adminUser.password);
        if (!isMatch) return res.status(400).json({ success: false, message: 'بيانات خاطئة' });

        const token = jwt.sign({ id: adminUser.id, role: 'admin' }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('admin_token', token, { httpOnly: true, maxAge: 7200000 });
        
        return res.json({ success: true, redirectUrl: '/admin/home-admin/home-admin.html' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// ---------------------------------------------------------
// 8. API: إدارة التصنيفات (Categories)
// ---------------------------------------------------------

// جلب التصنيفات
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM categories ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// إضافة تصنيف (للأدمن فقط)
app.post('/api/admin/categories', adminAuth, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ success: false, message: 'الاسم مطلوب' });
        
        await pool.query('INSERT INTO categories (name) VALUES ($1)', [name]);
        res.json({ success: true, message: 'تمت إضافة التصنيف' });
    } catch (err) {
        // التحقق من تكرار الاسم
        if (err.code === '23505') {
            return res.status(400).json({ success: false, message: 'هذا التصنيف موجود بالفعل' });
        }
        res.status(500).json({ success: false, message: err.message });
    }
});

// حذف تصنيف (للأدمن فقط)
app.delete('/api/admin/categories/:id', adminAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM categories WHERE id = $1', [req.params.id]);
        res.json({ success: true, message: 'تم حذف التصنيف' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ---------------------------------------------------------
// 9. API: المنتجات (عامة - للجميع)
// ---------------------------------------------------------

// جلب كل المنتجات
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// جلب منتج واحد
app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (isNaN(id)) return res.status(400).json({ message: 'Invalid ID' });

        const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'المنتج غير موجود' });

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------------------------------------------------------
// 10. API: إدارة المنتجات (محمية للأدمن فقط)
// ---------------------------------------------------------
// ---------------------------------------------------------
// 10. API: إدارة المنتجات (تحديث شامل)
// ---------------------------------------------------------

// إضافة منتج
app.post('/api/admin/add-product', adminAuth, upload.array('images', 5), async (req, res) => {
    try {
        const { name, description, price, discount_price, sizes, colors, category, rating, image_map } = req.body;
        
        const imagesPaths = req.files.map(file => '/uploads/' + file.filename);
        
        let colorsArray = [], sizesArray = [];
        try { if(colors) colorsArray = JSON.parse(colors); } catch(e){}
        try { if(sizes) sizesArray = JSON.parse(sizes); } catch(e){}

        // ملاحظة: في الإضافة الجديدة لا يمكن ربط الصور بالألوان مباشرة لأن الصور لم ترفع بعد
        // لذلك image_map سيكون فارغاً في البداية، ويتم ضبطه عند التعديل

        const query = `
            INSERT INTO products 
            (name, description, price, discount_price, category, rating, images, colors, sizes, image_map) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
            RETURNING *
        `;
        const values = [
            name, description, parseFloat(price), 
            discount_price ? parseFloat(discount_price) : null,
            category, parseFloat(rating) || 5.0,
            imagesPaths, colorsArray, sizesArray, 
            image_map || '{}' // حفظ الخريطة أو كائن فارغ
        ];

        await pool.query(query, values);
        res.json({ success: true, message: '✅ تمت الإضافة (اضغط تعديل لربط الألوان بالصور)' });

    } catch (err) {
        console.error("Add Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// تعديل منتج
 

app.put('/api/admin/product/:id', adminAuth, upload.array('images', 5), async (req, res) => {
    try {
        const { id } = req.params;
        // نستقبل البيانات من الـ Front-end
        const { name, description, price, discount_price, sizes, colors, category, rating, image_map, oldImages } = req.body;

        // 1. جلب بيانات المنتج الحالية من قاعدة البيانات (للحصول على الصور القديمة المخزنة فعلياً)
        const productResult = await pool.query('SELECT images FROM products WHERE id = $1', [id]);
        
        if (productResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'المنتج غير موجود' });
        }

        const currentDbImages = productResult.rows[0].images || []; // الصور الموجودة حالياً في السيرفر

        // 2. تجهيز مسارات الصور الجديدة (إن وجدت)
        let newImagesPaths = [];
        if (req.files && req.files.length > 0) {
            newImagesPaths = req.files.map(file => '/uploads/' + file.filename);
        }

        // 3. معالجة الصور القديمة التي أبقى عليها المستخدم
        let keptOldImages = [];
        if (oldImages) {
            try { 
                keptOldImages = JSON.parse(oldImages); 
            } catch(e) { 
                keptOldImages = Array.isArray(oldImages) ? oldImages : [oldImages]; 
            }
        }

        // 4. القائمة النهائية للصور التي سيتم حفظها في قاعدة البيانات
        const finalImages = keptOldImages.concat(newImagesPaths);

        // 5. عملية الحذف: تحديد الصور التي كانت في قاعدة البيانات ولم تعد موجودة في القائمة النهائية
        const imagesToDelete = currentDbImages.filter(img => !finalImages.includes(img));

        // تنفيذ الحذف الفعلي من المجلد
        imagesToDelete.forEach(imageUrl => {
            // imageUrl يكون مثل: /uploads/image.jpg
            const filename = imageUrl.split('/').pop(); // استخراج اسم الملف فقط

            // تحديد المسار الصحيح بناءً على هيكلية مشروعك
            // بما أن المجلد front-end بجانب ملف السيرفر (أو في الجذر)، نحدد المسار كالتالي:
            const filePath = path.join(__dirname, '../front-end/user/uploads', filename);
            // ملاحظة: إذا كان ملف السيرفر في الجذر مباشرة وليس داخل مجلد، احذف ".." من المسار أعلاه لتصبح:
            // path.join(__dirname, 'front-end/user/uploads', filename);

            fs.unlink(filePath, (err) => {
                if (err && err.code !== 'ENOENT') {
                    // ENOENT تعني الملف غير موجود أصلاً، نتجاهلها
                    console.error(`خطأ في حذف الملف: ${filename}`, err);
                } else if (!err) {
                    console.log(`تم حذف الصورة القديمة: ${filename}`);
                }
            });
        });

        // 6. تجهيز باقي البيانات (Colors & Sizes)
        let colorsArray = [], sizesArray = [];
        try { if(colors) colorsArray = JSON.parse(colors); } catch(e){}
        try { if(sizes) sizesArray = JSON.parse(sizes); } catch(e){}

        // 7. جملة التحديث في قاعدة البيانات
        const query = `
            UPDATE products SET 
            name=$1, description=$2, price=$3, discount_price=$4, 
            category=$5, rating=$6, colors=$7, sizes=$8, 
            images=$9, image_map=$10 
            WHERE id=$11
        `;
        
        const values = [
            name, description, price, discount_price || null, 
            category, rating, colorsArray, sizesArray, 
            finalImages, // القائمة الجديدة الكاملة
            image_map,
            id
        ];

        await pool.query(query, values);
        res.json({ success: true, message: '✅ تم التعديل وحذف الصور غير المستخدمة' });

    } catch (err) {
        console.error("Update Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

 // =========================================================
// 10. API: إدارة المنتجات (النسخة المحسنة والذكية)
// =========================================================

// دالة مساعدة لحذف الملفات من السيرفر
const deleteFileFromServer = (filePath) => {
    if (!filePath) return;
    const fileName = path.basename(filePath);
    const fullPath = path.join(__dirname, 'front-end', 'user', 'uploads', fileName);
    if (fs.existsSync(fullPath)) {
        fs.unlink(fullPath, (err) => {
            if (err) console.error(`Error deleting file: ${fileName}`, err);
            else console.log(`🗑️ Deleted file: ${fileName}`);
        });
    }
};

// أ) إضافة منتج (مع حماية من الملفات الزائدة عند الفشل)
app.post('/api/admin/add-product', adminAuth, upload.array('images', 5), async (req, res) => {
    try {
        const { name, description, price, discount_price, sizes, colors, category, rating, image_map } = req.body;
        
        // تحويل الملفات المرفوعة إلى مسارات
        const imagesPaths = req.files.map(file => '/uploads/' + file.filename);

        // تحليل البيانات
        let colorsArray = [], sizesArray = [];
        try { if(colors) colorsArray = JSON.parse(colors); } catch(e){}
        try { if(sizes) sizesArray = JSON.parse(sizes); } catch(e){}

        const query = `
            INSERT INTO products 
            (name, description, price, discount_price, category, rating, images, colors, sizes, image_map) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
            RETURNING *
        `;
        const values = [
            name, description, parseFloat(price), 
            discount_price ? parseFloat(discount_price) : null,
            category, parseFloat(rating) || 5.0,
            imagesPaths, colorsArray, sizesArray, 
            image_map || '{}'
        ];

        await pool.query(query, values);
        res.json({ success: true, message: '✅ تمت الإضافة بنجاح' });

    } catch (err) {
        console.error("Add Error:", err);
        // تنظيف: إذا فشلت الإضافة لقاعدة البيانات، نحذف الصور التي تم رفعها لتوها لتجنب تراكم الملفات
        if (req.files) {
            req.files.forEach(file => deleteFileFromServer('/uploads/' + file.filename));
        }
        res.status(500).json({ success: false, message: err.message });
    }
});

// ب) تعديل منتج (الحل الجذري لمشكلة التضاعف والصور غير المرتبطة)
app.put('/api/admin/product/:id', adminAuth, upload.array('images', 5), async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, price, discount_price, sizes, colors, category, rating, image_map, oldImages } = req.body;

        // 1. جلب الصور الحالية الموجودة في قاعدة البيانات (قبل التعديل)
        const currentProduct = await pool.query('SELECT images FROM products WHERE id = $1', [id]);
        if (currentProduct.rows.length === 0) return res.status(404).json({ success: false, message: 'المنتج غير موجود' });
        
        // الصور المسجلة حالياً في النظام
        const dbExistingImages = currentProduct.rows[0].images || [];

        // 2. تحديد الصور التي اختار المستخدم الاحتفاظ بها (oldImages)
        let keptOldImages = [];
        if (oldImages) {
            try { keptOldImages = JSON.parse(oldImages); } catch(e) { 
                keptOldImages = Array.isArray(oldImages) ? oldImages : [oldImages]; 
            }
        }
        // إزالة التكرار من الصور القديمة (حماية إضافية)
        keptOldImages = [...new Set(keptOldImages)];

        // 3. تحديد الصور الجديدة المرفوعة الآن
        let newImagesPaths = [];
        if (req.files && req.files.length > 0) {
            newImagesPaths = req.files.map(file => '/uploads/' + file.filename);
        }

        // 4. القائمة النهائية: القديم الذي أبقينا عليه + الجديد
        const finalImages = keptOldImages.concat(newImagesPaths);

        // 5. تنظيف الملفات (Garbage Collection):
        // أي صورة كانت موجودة في قاعدة البيانات (dbExistingImages)
        // ولم تعد موجودة في القائمة النهائية (finalImages) => يجب حذفها من المجلد
        dbExistingImages.forEach(dbImg => {
            if (!finalImages.includes(dbImg)) {
                deleteFileFromServer(dbImg); // حذف فعلي من القرص
            }
        });

        // 6. تحديث قاعدة البيانات
        let colorsArray = [], sizesArray = [];
        try { if(colors) colorsArray = JSON.parse(colors); } catch(e){}
        try { if(sizes) sizesArray = JSON.parse(sizes); } catch(e){}

        const query = `
            UPDATE products SET 
            name=$1, description=$2, price=$3, discount_price=$4, 
            category=$5, rating=$6, colors=$7, sizes=$8, 
            images=$9, image_map=$10 
            WHERE id=$11
        `;
        
        const values = [
            name, description, price, discount_price || null, 
            category, rating, colorsArray, sizesArray, 
            finalImages, // القائمة النظيفة والجديدة
            image_map, 
            id
        ];

        await pool.query(query, values);
        res.json({ success: true, message: '✅ تم التعديل وتنظيف الصور القديمة' });

    } catch (err) {
        console.error("Update Error:", err);
        // تنظيف: إذا فشل التعديل، نحذف الصور الجديدة التي رفعت للتو
        if (req.files) {
            req.files.forEach(file => deleteFileFromServer('/uploads/' + file.filename));
        }
        res.status(500).json({ success: false, message: err.message });
    }
});

// ج) حذف منتج (مع حذف كافة صوره)
app.delete('/api/admin/product/:id', adminAuth, async (req, res) => {
    try {
        const id = req.params.id;

        // 1. جلب الصور أولاً
        const result = await pool.query('SELECT images FROM products WHERE id = $1', [id]);

        if (result.rows.length > 0) {
            const images = result.rows[0].images;
            // حذف كل الصور من المجلد
            if (Array.isArray(images)) {
                images.forEach(img => deleteFileFromServer(img));
            } else if (typeof images === 'string') {
                try {
                    JSON.parse(images).forEach(img => deleteFileFromServer(img));
                } catch(e) { deleteFileFromServer(images); }
            }
        }

        // 2. حذف من القاعدة
        await pool.query('DELETE FROM products WHERE id = $1', [id]);
        
        res.json({ success: true, message: 'تم حذف المنتج وصوره' });

    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ---------------------------------------------------------
// 11. API: استقبال الطلبات (Checkout)
// ---------------------------------------------------------
app.post('/api/orders', async (req, res) => {
    try {
        const { 
            product_id, color, size, quantity, 
            customer_name, customer_phone, 
            country, state, city, address_details, notes 
        } = req.body;

        // 1. التحقق من صحة البيانات
        if (!product_id || !customer_name || !customer_phone) {
            return res.status(400).json({ success: false, message: 'يرجى ملء كافة البيانات الضرورية' });
        }

        // 2. جلب سعر المنتج الحقيقي من قاعدة البيانات (لا نعتمد على السعر القادم من المتصفح)
        const productResult = await pool.query('SELECT * FROM products WHERE id = $1', [product_id]);
        
        if (productResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'المنتج غير موجود' });
        }

        const product = productResult.rows[0];
        
        // تحديد السعر (هل يوجد تخفيض؟)
        // نحول القيم إلى أرقام عشرية لضمان الدقة
        const originalPrice = parseFloat(product.price);
        const discountPrice = product.discount_price ? parseFloat(product.discount_price) : null;
        
        // السعر المعتمد للوحدة
        const unitPrice = (discountPrice !== null && discountPrice < originalPrice) ? discountPrice : originalPrice;
        
        // حساب الإجمالي
        const qty = parseInt(quantity) || 1;
        const totalPrice = unitPrice * qty;
        
        // صورة المنتج (الأولى أو الموجودة في الـ Map إذا أردت تعقيداً أكثر، سنأخذ الأولى حالياً)
        const productImage = (product.images && product.images.length > 0) ? product.images[0] : '';

        // 3. إدخال الطلب في قاعدة البيانات
        const query = `
            INSERT INTO orders 
            (product_id, product_name, product_image, selected_color, selected_size, quantity, unit_price, total_price, 
             customer_name, customer_phone, country, state, city, address_details, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id
        `;
        
        const values = [
            product_id, product.name, productImage, color, size, qty, unitPrice, totalPrice,
            customer_name, customer_phone, country, state, city, address_details, notes
        ];

        const orderRes = await pool.query(query, values);
        
        res.json({ success: true, message: 'تم استلام طلبك بنجاح!', orderId: orderRes.rows[0].id });

    } catch (err) {
        console.error("Order Error:", err);
        res.status(500).json({ success: false, message: 'حدث خطأ في السيرفر' });
    }
});

// ---------------------------------------------------------
// 12. API: إدارة الطلبات (للأدمن فقط)
// ---------------------------------------------------------

// أ) جلب جميع الطلبات
app.get('/api/admin/orders', adminAuth, async (req, res) => {
    try {
        // نجلب الطلبات مرتبة من الأحدث إلى الأقدم
        const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ب) تحديث حالة الطلب (تأكيد، شحن، تسليم، إلغاء)
app.put('/api/admin/orders/:id/status', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body; // pending, confirmed, shipped, delivered, cancelled

        // التحقق من القيم المسموح بها
        const allowedStatuses = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
        if (!allowedStatuses.includes(status)) {
            return res.status(400).json({ success: false, message: 'حالة غير صالحة' });
        }

        await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, id]);
        res.json({ success: true, message: 'تم تحديث حالة الطلب' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ج) حذف طلب نهائياً
app.delete('/api/admin/orders/:id', adminAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM orders WHERE id = $1', [req.params.id]);
        res.json({ success: true, message: 'تم حذف الطلب' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});
 

// تشغيل السيرفر
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`🌍 Public: http://localhost:${PORT}/`);
    console.log(`🔒 Admin:  http://localhost:${PORT}/admin/home-admin/home-admin.html`);
});