const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuration PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialiser la base de données
async function initDatabase() {
    const client = await pool.connect();
    try {
        // Table des clés de licence
        await client.query(`
            CREATE TABLE IF NOT EXISTS license_keys (
                license_key VARCHAR(50) PRIMARY KEY,
                owner VARCHAR(255) NOT NULL,
                active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT NOW(),
                last_used TIMESTAMP,
                last_heartbeat TIMESTAMP,
                last_ip VARCHAR(45)
            )
        `);

        // Table des logs
        await client.query(`
            CREATE TABLE IF NOT EXISTS access_logs (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(50) NOT NULL,
                action VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45),
                timestamp TIMESTAMP DEFAULT NOW()
            )
        `);

        // Ajouter la colonne ip_address si elle n'existe pas (migration compatible PostgreSQL)
        try {
            await client.query(`
                ALTER TABLE access_logs
                ADD COLUMN ip_address VARCHAR(45)
            `);
            console.log('✅ Colonne ip_address ajoutée');
        } catch (error) {
            // La colonne existe déjà, c'est normal
            if (error.code !== '42701') { // 42701 = duplicate_column
                console.error('⚠️ Erreur migration ip_address:', error.message);
            }
        }

        // Table des IPs utilisées par clé
        await client.query(`
            CREATE TABLE IF NOT EXISTS key_ips (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                first_seen TIMESTAMP DEFAULT NOW(),
                last_seen TIMESTAMP DEFAULT NOW(),
                UNIQUE(license_key, ip_address)
            )
        `);

        // Table des utilisateurs invités
        await client.query(`
            CREATE TABLE IF NOT EXISTS guest_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                created_by VARCHAR(50) DEFAULT 'admin',
                last_login TIMESTAMP
            )
        `);

        console.log('✅ Base de données initialisée');
    } catch (error) {
        console.error('❌ Erreur initialisation BDD:', error);
    } finally {
        client.release();
    }
}

// Log d'utilisation avec IP
async function logAccess(licenseKey, action, status, ipAddress = null) {
    try {
        await pool.query(
            'INSERT INTO access_logs (license_key, action, status, ip_address) VALUES ($1, $2, $3, $4)',
            [licenseKey, action, status, ipAddress]
        );
    } catch (error) {
        console.error('Erreur log:', error);
    }
}

// Enregistrer ou mettre à jour l'IP d'une clé
async function trackIP(licenseKey, ipAddress) {
    try {
        await pool.query(`
            INSERT INTO key_ips (license_key, ip_address, first_seen, last_seen)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (license_key, ip_address)
            DO UPDATE SET last_seen = NOW()
        `, [licenseKey, ipAddress]);
    } catch (error) {
        console.error('Erreur track IP:', error);
    }
}

// ===== ROUTES API =====

// Vérifier une clé de licence
app.post('/api/verify', async (req, res) => {
    const { licenseKey } = req.body;

    if (!licenseKey) {
        return res.status(400).json({
            valid: false,
            message: 'Clé de licence manquante'
        });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM license_keys WHERE license_key = $1',
            [licenseKey]
        );

        if (result.rows.length === 0) {
            await logAccess(licenseKey, 'verify', 'invalid_key');
            return res.json({
                valid: false,
                message: 'Clé de licence invalide'
            });
        }

        const keyData = result.rows[0];

        if (!keyData.active) {
            await logAccess(licenseKey, 'verify', 'inactive');
            return res.json({
                valid: false,
                message: 'Clé de licence désactivée'
            });
        }

        // Mettre à jour la dernière utilisation
        await pool.query(
            'UPDATE license_keys SET last_used = NOW() WHERE license_key = $1',
            [licenseKey]
        );

        await logAccess(licenseKey, 'verify', 'success');

        res.json({
            valid: true,
            message: 'Clé de licence valide',
            owner: keyData.owner
        });
    } catch (error) {
        console.error('Erreur verify:', error);
        res.status(500).json({
            valid: false,
            message: 'Erreur serveur'
        });
    }
});

// ===== ROUTES ADMIN =====

const ADMIN_PASSWORD = 'admin123';

function checkAdminAuth(req, res, next) {
    const { password } = req.body;

    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({
            success: false,
            message: 'Mot de passe incorrect'
        });
    }

    next();
}

// Liste toutes les clés
app.post('/api/admin/keys', checkAdminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM license_keys ORDER BY created_at DESC'
        );

        const keys = {};
        result.rows.forEach(row => {
            keys[row.license_key] = {
                owner: row.owner,
                active: row.active,
                createdAt: row.created_at,
                lastUsed: row.last_used
            };
        });

        res.json({
            success: true,
            keys: keys
        });
    } catch (error) {
        console.error('Erreur keys:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Créer une nouvelle clé
app.post('/api/admin/create-key', checkAdminAuth, async (req, res) => {
    const { owner } = req.body;

    if (!owner) {
        return res.status(400).json({
            success: false,
            message: 'Nom du propriétaire requis'
        });
    }

    try {
        const licenseKey = 'TW-' + Math.random().toString(36).substring(2, 15).toUpperCase();

        await pool.query(
            'INSERT INTO license_keys (license_key, owner, active) VALUES ($1, $2, true)',
            [licenseKey, owner]
        );

        res.json({
            success: true,
            licenseKey,
            message: 'Clé créée avec succès'
        });
    } catch (error) {
        console.error('Erreur create-key:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Activer/Désactiver une clé
app.post('/api/admin/toggle-key', checkAdminAuth, async (req, res) => {
    const { licenseKey } = req.body;

    try {
        const result = await pool.query(
            'SELECT active FROM license_keys WHERE license_key = $1',
            [licenseKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Clé non trouvée'
            });
        }

        const newActive = !result.rows[0].active;

        await pool.query(
            'UPDATE license_keys SET active = $1 WHERE license_key = $2',
            [newActive, licenseKey]
        );

        await logAccess(licenseKey, 'toggle', newActive ? 'activated' : 'deactivated');

        res.json({
            success: true,
            active: newActive,
            message: `Clé ${newActive ? 'activée' : 'désactivée'}`
        });
    } catch (error) {
        console.error('Erreur toggle:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer une clé
app.post('/api/admin/delete-key', checkAdminAuth, async (req, res) => {
    const { licenseKey } = req.body;

    try {
        const result = await pool.query(
            'DELETE FROM license_keys WHERE license_key = $1 RETURNING *',
            [licenseKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Clé non trouvée'
            });
        }

        await logAccess(licenseKey, 'delete', 'success');

        res.json({
            success: true,
            message: 'Clé supprimée'
        });
    } catch (error) {
        console.error('Erreur delete:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Voir les logs
app.post('/api/admin/logs', checkAdminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 100'
        );

        res.json({
            success: true,
            logs: result.rows
        });
    } catch (error) {
        console.error('Erreur logs:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Heartbeat - signaler que l'extension est en ligne
app.post('/api/heartbeat', async (req, res) => {
    const { licenseKey } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!licenseKey) {
        return res.status(400).json({
            success: false,
            message: 'Clé de licence manquante'
        });
    }

    try {
        // Mettre à jour le heartbeat
        await pool.query(
            'UPDATE license_keys SET last_heartbeat = NOW(), last_ip = $2 WHERE license_key = $1',
            [licenseKey, ipAddress]
        );

        // Enregistrer l'IP
        await trackIP(licenseKey, ipAddress);

        res.json({
            success: true,
            message: 'Heartbeat enregistré'
        });
    } catch (error) {
        console.error('Erreur heartbeat:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Stats admin avec statut en ligne et IPs
app.post('/api/admin/detailed-stats', checkAdminAuth, async (req, res) => {
    try {
        const keysResult = await pool.query(`
            SELECT
                license_key,
                owner,
                active,
                created_at,
                last_used,
                last_heartbeat,
                last_ip,
                (last_heartbeat > NOW() - INTERVAL '60 seconds') as is_online
            FROM license_keys
            ORDER BY created_at DESC
        `);

        const detailedStats = await Promise.all(keysResult.rows.map(async (key) => {
            // Compter les commentaires
            const commentsResult = await pool.query(
                'SELECT COUNT(*) as count FROM access_logs WHERE license_key = $1 AND action = $2',
                [key.license_key, 'comment_posted']
            );

            // Compter les IPs uniques
            const ipsResult = await pool.query(
                'SELECT COUNT(DISTINCT ip_address) as count FROM key_ips WHERE license_key = $1',
                [key.license_key]
            );

            // Récupérer les IPs
            const ipsListResult = await pool.query(
                'SELECT ip_address, first_seen, last_seen FROM key_ips WHERE license_key = $1 ORDER BY last_seen DESC',
                [key.license_key]
            );

            return {
                licenseKey: key.license_key,
                owner: key.owner,
                active: key.active,
                createdAt: key.created_at,
                lastUsed: key.last_used,
                lastHeartbeat: key.last_heartbeat,
                lastIp: key.last_ip,
                isOnline: key.is_online,
                commentsCount: parseInt(commentsResult.rows[0].count),
                uniqueIps: parseInt(ipsResult.rows[0].count),
                ips: ipsListResult.rows
            };
        }));

        res.json({
            success: true,
            stats: detailedStats
        });
    } catch (error) {
        console.error('Erreur detailed-stats:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Enregistrer un commentaire posté
app.post('/api/log-comment', async (req, res) => {
    const { licenseKey } = req.body;

    if (!licenseKey) {
        return res.status(400).json({
            success: false,
            message: 'Clé de licence manquante'
        });
    }

    try {
        // Vérifier que la clé existe
        const result = await pool.query(
            'SELECT * FROM license_keys WHERE license_key = $1',
            [licenseKey]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Clé non trouvée'
            });
        }

        // Logger le commentaire
        await logAccess(licenseKey, 'comment_posted', 'success');

        res.json({
            success: true,
            message: 'Commentaire enregistré'
        });
    } catch (error) {
        console.error('Erreur log-comment:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Statistiques publiques (sans authentification)
app.get('/api/stats', async (req, res) => {
    try {
        // Récupérer toutes les clés actives
        const keysResult = await pool.query(
            'SELECT license_key, owner, created_at FROM license_keys WHERE active = true ORDER BY created_at DESC'
        );

        // Pour chaque clé, compter les commentaires
        const stats = await Promise.all(keysResult.rows.map(async (key) => {
            const commentsResult = await pool.query(
                'SELECT COUNT(*) as count FROM access_logs WHERE license_key = $1 AND action = $2',
                [key.license_key, 'comment_posted']
            );

            return {
                owner: key.owner,
                licenseKey: key.license_key,
                commentsCount: parseInt(commentsResult.rows[0].count),
                createdAt: key.created_at
            };
        }));

        res.json({
            success: true,
            stats: stats
        });
    } catch (error) {
        console.error('Erreur stats:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ===== ROUTES INVITÉS =====

// Login (admin ou invité)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Vérifier si c'est l'admin
    if (username === 'admin' && password === ADMIN_PASSWORD) {
        return res.json({
            success: true,
            role: 'admin',
            username: 'admin'
        });
    }

    // Vérifier si c'est un invité
    try {
        const result = await pool.query(
            'SELECT * FROM guest_users WHERE username = $1 AND password = $2',
            [username, password]
        );

        if (result.rows.length > 0) {
            // Mettre à jour last_login
            await pool.query(
                'UPDATE guest_users SET last_login = NOW() WHERE username = $1',
                [username]
            );

            return res.json({
                success: true,
                role: 'guest',
                username: username
            });
        }

        res.json({
            success: false,
            message: 'Identifiants invalides'
        });
    } catch (error) {
        console.error('Erreur login:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Créer un invité (admin uniquement)
app.post('/api/admin/create-guest', checkAdminAuth, async (req, res) => {
    const { username, guestPassword } = req.body;

    if (!username || !guestPassword) {
        return res.status(400).json({
            success: false,
            message: 'Username et password requis'
        });
    }

    try {
        await pool.query(
            'INSERT INTO guest_users (username, password) VALUES ($1, $2)',
            [username, guestPassword]
        );

        res.json({
            success: true,
            message: 'Invité créé avec succès'
        });
    } catch (error) {
        if (error.code === '23505') { // Duplicate key
            return res.status(400).json({
                success: false,
                message: 'Ce nom d\'utilisateur existe déjà'
            });
        }
        console.error('Erreur create-guest:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Liste des invités (admin uniquement)
app.post('/api/admin/guests', checkAdminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, created_at, last_login FROM guest_users ORDER BY created_at DESC'
        );

        res.json({
            success: true,
            guests: result.rows
        });
    } catch (error) {
        console.error('Erreur guests:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Supprimer un invité (admin uniquement)
app.post('/api/admin/delete-guest', checkAdminAuth, async (req, res) => {
    const { username } = req.body;

    try {
        const result = await pool.query(
            'DELETE FROM guest_users WHERE username = $1 RETURNING *',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Invité non trouvé'
            });
        }

        res.json({
            success: true,
            message: 'Invité supprimé'
        });
    } catch (error) {
        console.error('Erreur delete-guest:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Remettre à zéro les commentaires d'une licence
app.post('/api/admin/reset-comments', checkAdminAuth, async (req, res) => {
    const { licenseKey } = req.body;

    if (!licenseKey) {
        return res.status(400).json({
            success: false,
            message: 'Clé de licence requise'
        });
    }

    try {
        // Supprimer tous les logs de commentaires pour cette licence
        const result = await pool.query(
            'DELETE FROM access_logs WHERE license_key = $1 AND action = $2 RETURNING *',
            [licenseKey, 'comment_posted']
        );

        console.log(`✅ ${result.rowCount} commentaires supprimés pour ${licenseKey}`);

        res.json({
            success: true,
            message: `${result.rowCount} commentaire(s) supprimé(s)`,
            deletedCount: result.rowCount
        });
    } catch (error) {
        console.error('Erreur reset-comments:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// Démarrer le serveur
async function startServer() {
    await initDatabase();

    app.listen(PORT, () => {
        console.log(`🔐 Serveur de licences démarré sur http://localhost:${PORT}`);
        console.log(`📊 Panneau admin: http://localhost:${PORT}/admin.html`);
        console.log(`🔑 Mot de passe admin: ${ADMIN_PASSWORD}`);
    });
}

startServer();
