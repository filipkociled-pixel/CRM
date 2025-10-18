const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_placeholder');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database('./crm.db', (err) => {
    if (err) {
        console.error('Chyba při připojení k databázi:', err);
    } else {
        console.log('✅ Databáze připojena');
        initDatabase();
    }
});

function initDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_premium BOOLEAN DEFAULT 0,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        api_key TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        title TEXT,
        profile_url TEXT,
        note TEXT,
        saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        messages_sent INTEGER DEFAULT 0,
        contacts_saved INTEGER DEFAULT 0,
        templates_used INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
}

function generateApiKey() {
    return 'lcrm_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token chybí' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Neplatný token' });
        req.user = user;
        next();
    });
}

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email a heslo jsou povinné' });
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = generateApiKey();
        
        db.run('INSERT INTO users (email, password, api_key) VALUES (?, ?, ?)', [email, hashedPassword, apiKey], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email již existuje' });
                return res.status(500).json({ error: 'Chyba serveru' });
            }
            db.run('INSERT INTO stats (user_id) VALUES (?)', [this.lastID]);
            const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
            res.json({ success: true, token, apiKey, user: { id: this.lastID, email, isPremium: false } });
        });
    } catch (error) {
        res.status(500).json({ error: 'Chyba při registraci' });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Špatný email nebo heslo' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Špatný email nebo heslo' });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
        res.json({ success: true, token, apiKey: user.api_key, user: { id: user.id, email: user.email, isPremium: user.is_premium === 1 } });
    });
});

app.post('/api/verify-premium', (req, res) => {
    const { apiKey } = req.body;
    db.get('SELECT is_premium FROM users WHERE api_key = ?', [apiKey], (err, user) => {
        if (err || !user) return res.json({ isPremium: false });
        res.json({ isPremium: user.is_premium === 1 });
    });
});

app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        let customerId;
        
        db.get('SELECT stripe_customer_id FROM users WHERE id = ?', [userId], async (err, user) => {
            if (user && user.stripe_customer_id) {
                customerId = user.stripe_customer_id;
            } else {
                const customer = await stripe.customers.create({ email: req.user.email, metadata: { userId: userId.toString() } });
                customerId = customer.id;
                db.run('UPDATE users SET stripe_customer_id = ? WHERE id = ?', [customerId, userId]);
            }
            
            const session = await stripe.checkout.sessions.create({
                customer: customerId,
                payment_method_types: ['card'],
                line_items: [{
                    price_data: {
                        currency: 'usd',
                        product_data: { name: 'LinkedIn Sales CRM Premium', description: 'Měsíční předplatné' },
                        unit_amount: 1200,
                        recurring: { interval: 'month' }
                    },
                    quantity: 1
                }],
                mode: 'subscription',
                success_url: 'https://your-website.com/success?session_id={CHECKOUT_SESSION_ID}',
                cancel_url: 'https://your-website.com/pricing',
                metadata: { userId: userId.toString() }
            });
            
            res.json({ sessionId: session.id, url: session.url });
        });
    } catch (error) {
        console.error('Stripe chyba:', error);
        res.status(500).json({ error: 'Chyba při vytváření platby' });
    }
});

app.get('/api/templates', authenticateToken, (req, res) => {
    db.all('SELECT * FROM templates WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, templates) => {
        if (err) return res.status(500).json({ error: 'Chyba při načítání šablon' });
        res.json({ templates });
    });
});

app.post('/api/templates', authenticateToken, (req, res) => {
    const { name, text } = req.body;
    const userId = req.user.id;
    
    const insertTemplate = () => {
        db.run('INSERT INTO templates (user_id, name, text) VALUES (?, ?, ?)', [userId, name, text], function(err) {
            if (err) return res.status(500).json({ error: 'Chyba při vytváření šablony' });
            res.json({ success: true, template: { id: this.lastID, name, text } });
        });
    };
    
    db.get('SELECT is_premium FROM users WHERE id = ?', [userId], (err, user) => {
        if (!user.is_premium) {
            db.get('SELECT COUNT(*) as count FROM templates WHERE user_id = ?', [userId], (err, result) => {
                if (result.count >= 5) return res.status(403).json({ error: 'Limit 5 šablon. Přejděte na Premium.' });
                insertTemplate();
            });
        } else {
            insertTemplate();
        }
    });
});

app.delete('/api/templates/:id', authenticateToken, (req, res) => {
    db.run('DELETE FROM templates WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function(err) {
        if (err) return res.status(500).json({ error: 'Chyba při mazání' });
        if (this.changes === 0) return res.status(404).json({ error: 'Šablona nenalezena' });
        res.json({ success: true });
    });
});

app.get('/api/contacts', authenticateToken, (req, res) => {
    db.all('SELECT * FROM contacts WHERE user_id = ? ORDER BY saved_at DESC', [req.user.id], (err, contacts) => {
        if (err) return res.status(500).json({ error: 'Chyba při načítání kontaktů' });
        res.json({ contacts });
    });
});

app.post('/api/contacts', authenticateToken, (req, res) => {
    const { name, title, profile_url, note } = req.body;
    const userId = req.user.id;
    
    const insertContact = () => {
        db.run('INSERT INTO contacts (user_id, name, title, profile_url, note) VALUES (?, ?, ?, ?, ?)', [userId, name, title, profile_url, note], function(err) {
            if (err) return res.status(500).json({ error: 'Chyba při ukládání kontaktu' });
            db.run('UPDATE stats SET contacts_saved = contacts_saved + 1 WHERE user_id = ?', [userId]);
            res.json({ success: true, contact: { id: this.lastID, name, title, profile_url, note } });
        });
    };
    
    db.get('SELECT is_premium FROM users WHERE id = ?', [userId], (err, user) => {
        if (!user.is_premium) {
            db.get('SELECT COUNT(*) as count FROM contacts WHERE user_id = ?', [userId], (err, result) => {
                if (result.count >= 50) return res.status(403).json({ error: 'Limit 50 kontaktů. Přejděte na Premium.' });
                insertContact();
            });
        } else {
            insertContact();
        }
    });
});

app.get('/api/contacts/export', authenticateToken, (req, res) => {
    db.get('SELECT is_premium FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (!user.is_premium) return res.status(403).json({ error: 'Pouze pro Premium uživatele' });
        db.all('SELECT name, title, profile_url, note, saved_at FROM contacts WHERE user_id = ?', [req.user.id], (err, contacts) => {
            if (err) return res.status(500).json({ error: 'Chyba při exportu' });
            let csv = 'Name,Title,Profile URL,Note,Saved At\n';
            contacts.forEach(c => {
                csv += `"${c.name}","${c.title || ''}","${c.profile_url || ''}","${c.note || ''}","${c.saved_at}"\n`;
            });
            res.header('Content-Type', 'text/csv');
            res.header('Content-Disposition', 'attachment; filename=contacts.csv');
            res.send(csv);
        });
    });
});

app.get('/api/stats', authenticateToken, (req, res) => {
    db.get('SELECT * FROM stats WHERE user_id = ?', [req.user.id], (err, stats) => {
        if (err) return res.status(500).json({ error: 'Chyba při načítání statistik' });
        res.json({ stats: stats || { messages_sent: 0, contacts_saved: 0, templates_used: 0 } });
    });
});

app.get('/', (req, res) => {
    res.json({ 
        message: '🚀 LinkedIn CRM Backend API',
        status: 'running',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            auth: { register: 'POST /api/auth/register', login: 'POST /api/auth/login' },
            premium: 'POST /api/verify-premium',
            templates: 'GET/POST /api/templates',
            contacts: 'GET/POST /api/contacts'
        }
    });
});

app.get('/api/health', (req, res) => {
    res.json({ status: '✅ healthy', timestamp: new Date().toISOString(), database: 'connected' });
});

app.listen(PORT, () => {
    console.log(`🚀 Server běží na http://localhost:${PORT}`);
});
