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
                last_used TIMESTAMP
            )
        `);

        // Table des logs
        await client.query(`
            CREATE TABLE IF NOT EXISTS access_logs (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(50) NOT NULL,
                action VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                timestamp TIMESTAMP DEFAULT NOW()
            )
        `);

        console.log('✅ Base de données initialisée');
    } catch (error) {
        console.error('❌ Erreur initialisation BDD:', error);
    } finally {
        client.release();
    }
}

// Log d'utilisation
async function logAccess(licenseKey, action, status) {
    try {
        await pool.query(
            'INSERT INTO access_logs (license_key, action, status) VALUES ($1, $2, $3)',
            [licenseKey, action, status]
        );
    } catch (error) {
        console.error('Erreur log:', error);
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
