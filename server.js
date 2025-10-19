// ==================================================================
// LINKEDIN SALES CRM - BACKEND API S STRIPE
// ==================================================================

const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_YOUR_KEY_HERE'); // ← ZMĚŇ
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this'; // ← ZMĚŇ
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || 'whsec_YOUR_WEBHOOK_SECRET'; // ← ZMĚŇ

// Middleware
app.use(cors());
app.use(express.json());

// Webhook endpoint - MUSÍ být PŘED express.json()!
app.post('/api/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;
    
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('⚠️ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    console.log('✅ Webhook event:', event.type);
    
    // Zpracuj eventi
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;
            const userId = session.metadata.userId;
            
            console.log('💳 Platba dokončena pro user:', userId);
            
            // Aktivuj premium
            db.run(
                'UPDATE users SET is_premium = 1, stripe_subscription_id = ? WHERE id = ?',
                [session.subscription, userId],
                (err) => {
                    if (err) {
                        console.error('❌ Chyba při aktivaci premium:', err);
                    } else {
                        console.log('✅ Premium aktivováno pro user:', userId);
                    }
                }
            );
            break;
            
        case 'customer.subscription.deleted':
            const subscription = event.data.object;
            
            console.log('🚫 Předplatné zrušeno:', subscription.id);
            
            // Deaktivuj premium
            db.run(
                'UPDATE users SET is_premium = 0 WHERE stripe_subscription_id = ?',
                [subscription.id],
                (err) => {
                    if (err) {
                        console.error('❌ Chyba při deaktivaci premium:', err);
                    } else {
                        console.log('✅ Premium deaktivováno');
                    }
                }
            );
            break;
            
        case 'invoice.payment_succeeded':
            console.log('✅ Platba úspěšná');
            break;
            
        case 'invoice.payment_failed':
            const invoice = event.data.object;
            console.log('❌ Platba selhala pro:', invoice.customer);
            
            // Můžeš poslat email uživateli o selhání platby
            break;
    }
    
    res.json({received: true});
});

// ==================================================================
// DATABÁZE - SQLite
// ==================================================================
const db = new sqlite3.Database('./crm.db', (err) => {
    if (err) {
        console.error('Chyba při připojení k databázi:', err);
    } else {
        console.log('✅ Databáze připojena');
        initDatabase();
    }
});

function initDatabase() {
    // Tabulka uživatelů
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_premium BOOLEAN DEFAULT 0,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            api_key TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Tabulka šablon
    db.run(`
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    // Tabulka kontaktů
    db.run(`
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            title TEXT,
            profile_url TEXT,
            note TEXT,
            saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
    
    // Tabulka statistik
    db.run(`
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            messages_sent INTEGER DEFAULT 0,
            contacts_saved INTEGER DEFAULT 0,
            templates_used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);
}

// ==================================================================
// HELPER FUNKCE
// ==================================================================

function generateApiKey() {
    return 'lcrm_' + Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token chybí' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Neplatný token' });
        }
        req.user = user;
        next();
    });
}

// ==================================================================
// AUTH ENDPOINTY
// ==================================================================

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email a heslo jsou povinné' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const apiKey = generateApiKey();
        
        db.run(
            'INSERT INTO users (email, password, api_key) VALUES (?, ?, ?)',
            [email, hashedPassword, apiKey],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Email již existuje' });
                    }
                    return res.status(500).json({ error: 'Chyba serveru' });
                }
                
                db.run('INSERT INTO stats (user_id) VALUES (?)', [this.lastID]);
                
                const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
                
                res.json({
                    success: true,
                    token,
                    apiKey,
                    user: { id: this.lastID, email, isPremium: false }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Chyba při registraci' });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Špatný email nebo heslo' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(400).json({ error: 'Špatný email nebo heslo' });
        }
        
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
        
        res.json({
            success: true,
            token,
            apiKey: user.api_key,
            user: {
                id: user.id,
                email: user.email,
                isPremium: user.is_premium === 1
            }
        });
    });
});

// ==================================================================
// STRIPE CHECKOUT
// ==================================================================

app.post('/api/create-checkout-session', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        db.get('SELECT * FROM users WHERE id = ?', [userId], async (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'Uživatel nenalezen' });
            }
            
            let customerId = user.stripe_customer_id;
            
            // Vytvoř nebo najdi Stripe customer
            if (!customerId) {
                const customer = await stripe.customers.create({
                    email: user.email,
                    metadata: { userId: userId.toString() }
                });
                customerId = customer.id;
                
                db.run('UPDATE users SET stripe_customer_id = ? WHERE id = ?', 
                    [customerId, userId]);
            }
            
            // Vytvoř checkout session
            const session = await stripe.checkout.sessions.create({
                customer: customerId,
                payment_method_types: ['card'],
                line_items: [{
                    price: process.env.STRIPE_PRICE_ID || 'price_YOUR_PRICE_ID', // ← ZMĚŇ
                    quantity: 1
                }],
                mode: 'subscription',
                success_url: `${process.env.FRONTEND_URL || 'https://www.bedesk.cz'}/success.html?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.FRONTEND_URL || 'https://www.bedesk.cz'}/dashboard.html?canceled=true`,
                metadata: { userId: userId.toString() }
            });
            
            console.log('✅ Checkout session vytvořena:', session.id);
            
            res.json({ 
                sessionId: session.id, 
                url: session.url 
            });
        });
    } catch (error) {
        console.error('❌ Stripe error:', error);
        res.status(500).json({ error: 'Chyba při vytváření platby' });
    }
});

// Zrušení předplatného
app.post('/api/cancel-subscription', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        db.get('SELECT stripe_subscription_id FROM users WHERE id = ?', [userId], async (err, user) => {
            if (!user || !user.stripe_subscription_id) {
                return res.status(400).json({ error: 'Žádné aktivní předplatné' });
            }
            
            await stripe.subscriptions.cancel(user.stripe_subscription_id);
            
            db.run('UPDATE users SET is_premium = 0, stripe_subscription_id = NULL WHERE id = ?', [userId]);
            
            res.json({ success: true, message: 'Předplatné zrušeno' });
        });
    } catch (error) {
        console.error('Stripe error:', error);
        res.status(500).json({ error: 'Chyba při rušení předplatného' });
    }
});

// ==================================================================
// PREMIUM & OVĚŘENÍ
// ==================================================================

app.post('/api/verify-premium', (req, res) => {
    const { apiKey } = req.body;
    
    db.get('SELECT is_premium FROM users WHERE api_key = ?', [apiKey], (err, user) => {
        if (err || !user) {
            return res.json({ isPremium: false });
        }
        
        res.json({ isPremium: user.is_premium === 1 });
    });
});

// ==================================================================
// OSTATNÍ ENDPOINTY (templates, contacts, stats)
// Ponecháno z původního kódu...
// ==================================================================

app.get('/api/stats', authenticateToken, (req, res) => {
    db.get(
        'SELECT * FROM stats WHERE user_id = ?',
        [req.user.id],
        (err, stats) => {
            if (err) {
                return res.status(500).json({ error: 'Chyba při načítání statistik' });
            }
            
            res.json({ stats: stats || { messages_sent: 0, contacts_saved: 0, templates_used: 0 } });
        }
    );
});

// ==================================================================
// SPUŠTĚNÍ SERVERU
// ==================================================================

app.listen(PORT, () => {
    console.log(`🚀 Server běží na http://localhost:${PORT}`);
    console.log(`💳 Stripe mode: ${process.env.STRIPE_SECRET_KEY ? 'PRODUCTION' : 'TEST'}`);
});
