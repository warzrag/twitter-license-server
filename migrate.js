// Script de migration pour ajouter la colonne ip_address
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function migrate() {
    const client = await pool.connect();

    try {
        console.log('🔄 Début de la migration...');

        // Vérifier si la colonne existe
        const checkColumn = await client.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name='access_logs' AND column_name='ip_address'
        `);

        if (checkColumn.rows.length === 0) {
            console.log('📝 Ajout de la colonne ip_address...');

            // Ajouter la colonne
            await client.query(`
                ALTER TABLE access_logs
                ADD COLUMN ip_address VARCHAR(45)
            `);

            console.log('✅ Colonne ip_address ajoutée avec succès !');
        } else {
            console.log('✅ La colonne ip_address existe déjà');
        }

        console.log('✅ Migration terminée !');

    } catch (error) {
        console.error('❌ Erreur migration:', error);
        throw error;
    } finally {
        client.release();
        await pool.end();
    }
}

migrate();
