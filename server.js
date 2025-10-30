const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Fichier de stockage des clés
const KEYS_FILE = path.join(__dirname, 'keys.json');

// Initialiser le fichier des clés s'il n'existe pas
if (!fs.existsSync(KEYS_FILE)) {
    const initialData = {
        keys: {},
        logs: []
    };
    fs.writeFileSync(KEYS_FILE, JSON.stringify(initialData, null, 2));
}

// Lire les clés
function readKeys() {
    const data = fs.readFileSync(KEYS_FILE, 'utf8');
    return JSON.parse(data);
}

// Écrire les clés
function writeKeys(data) {
    fs.writeFileSync(KEYS_FILE, JSON.stringify(data, null, 2));
}

// Log d'utilisation
function logAccess(licenseKey, action, status) {
    const data = readKeys();
    data.logs.push({
        licenseKey,
        action,
        status,
        timestamp: new Date().toISOString()
    });

    // Garder seulement les 1000 derniers logs
    if (data.logs.length > 1000) {
        data.logs = data.logs.slice(-1000);
    }

    writeKeys(data);
}

// ===== ROUTES API =====

// Vérifier une clé de licence
app.post('/api/verify', (req, res) => {
    const { licenseKey } = req.body;

    if (!licenseKey) {
        return res.status(400).json({
            valid: false,
            message: 'Clé de licence manquante'
        });
    }

    const data = readKeys();
    const keyData = data.keys[licenseKey];

    if (!keyData) {
        logAccess(licenseKey, 'verify', 'invalid_key');
        return res.json({
            valid: false,
            message: 'Clé de licence invalide'
        });
    }

    if (!keyData.active) {
        logAccess(licenseKey, 'verify', 'inactive');
        return res.json({
            valid: false,
            message: 'Clé de licence désactivée'
        });
    }

    // Mettre à jour la dernière utilisation
    keyData.lastUsed = new Date().toISOString();
    writeKeys(data);

    logAccess(licenseKey, 'verify', 'success');

    res.json({
        valid: true,
        message: 'Clé de licence valide',
        owner: keyData.owner
    });
});

// ===== ROUTES ADMIN =====

// Mot de passe admin simple (à changer !)
const ADMIN_PASSWORD = 'admin123';

// Middleware pour vérifier le mot de passe admin
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
app.post('/api/admin/keys', checkAdminAuth, (req, res) => {
    const data = readKeys();
    res.json({
        success: true,
        keys: data.keys
    });
});

// Créer une nouvelle clé
app.post('/api/admin/create-key', checkAdminAuth, (req, res) => {
    const { owner } = req.body;

    if (!owner) {
        return res.status(400).json({
            success: false,
            message: 'Nom du propriétaire requis'
        });
    }

    // Générer une clé aléatoire
    const licenseKey = 'TW-' + Math.random().toString(36).substring(2, 15).toUpperCase();

    const data = readKeys();
    data.keys[licenseKey] = {
        owner,
        active: true,
        createdAt: new Date().toISOString(),
        lastUsed: null
    };

    writeKeys(data);

    res.json({
        success: true,
        licenseKey,
        message: 'Clé créée avec succès'
    });
});

// Activer/Désactiver une clé
app.post('/api/admin/toggle-key', checkAdminAuth, (req, res) => {
    const { licenseKey } = req.body;

    const data = readKeys();

    if (!data.keys[licenseKey]) {
        return res.status(404).json({
            success: false,
            message: 'Clé non trouvée'
        });
    }

    data.keys[licenseKey].active = !data.keys[licenseKey].active;
    writeKeys(data);

    logAccess(licenseKey, 'toggle', data.keys[licenseKey].active ? 'activated' : 'deactivated');

    res.json({
        success: true,
        active: data.keys[licenseKey].active,
        message: `Clé ${data.keys[licenseKey].active ? 'activée' : 'désactivée'}`
    });
});

// Supprimer une clé
app.post('/api/admin/delete-key', checkAdminAuth, (req, res) => {
    const { licenseKey } = req.body;

    const data = readKeys();

    if (!data.keys[licenseKey]) {
        return res.status(404).json({
            success: false,
            message: 'Clé non trouvée'
        });
    }

    delete data.keys[licenseKey];
    writeKeys(data);

    logAccess(licenseKey, 'delete', 'success');

    res.json({
        success: true,
        message: 'Clé supprimée'
    });
});

// Voir les logs
app.post('/api/admin/logs', checkAdminAuth, (req, res) => {
    const data = readKeys();
    res.json({
        success: true,
        logs: data.logs.slice(-100).reverse() // Les 100 derniers logs
    });
});

// Démarrer le serveur
app.listen(PORT, () => {
    console.log(`🔐 Serveur de licences démarré sur http://localhost:${PORT}`);
    console.log(`📊 Panneau admin: http://localhost:${PORT}/admin.html`);
    console.log(`🔑 Mot de passe admin: ${ADMIN_PASSWORD}`);
});
