#!/bin/bash

echo "🚀 Push vers GitHub..."

# Vérifier s'il y a des commits à pusher
if git log origin/main..HEAD --oneline | grep -q .; then
    echo "📦 Commits à pusher:"
    git log origin/main..HEAD --oneline
    echo ""

    # Demander confirmation
    read -p "Pusher ces commits vers GitHub ? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git push origin main

        if [ $? -eq 0 ]; then
            echo "✅ Push réussi !"
            echo "🔄 Railway va redéployer automatiquement dans 1-2 minutes"
            echo "📊 Vérifiez: https://twitter-license-server-production.up.railway.app/admin.html"
        else
            echo "❌ Erreur lors du push"
            echo "💡 Utilisez GitHub Desktop ou VSCode pour pusher manuellement"
        fi
    else
        echo "❌ Push annulé"
    fi
else
    echo "✅ Aucun commit à pusher, tout est à jour"
fi
