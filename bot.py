#!/usr/bin/env python3
"""
Telegram Bot for Firebase & API Key Extractor
Accepts APK files (single or bulk) and extracts Firebase credentials
Supports up to 20 APKs at once
"""

import os
import json
import logging
import tempfile
import zipfile
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)

from firebase_extractor import (
    extract_from_apk,
    generate_summary_report,
    get_firebase_configs_only,
    extract_multiple_apks
)
from firebase_checker import check_firebase_configs, generate_security_report

# ==================== Configuration ====================

BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable not set!")

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
PORT = int(os.environ.get("PORT", 10000))

# Create directories
DOWNLOAD_DIR = "./downloads"
REPORTS_DIR = "./reports"
TEMP_APK_DIR = "./temp_apks"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(TEMP_APK_DIR, exist_ok=True)

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot user data storage
user_data_store = {}

# Flask app for web server
app = Flask(__name__)


@app.route('/')
def home():
    """Home page for Render health check."""
    return {"status": "ok", "message": "Firebase Extractor Bot is running!"}


@app.route('/health')
def health():
    """Health check endpoint for Render."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ==================== Telegram Bot Handlers ====================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message when /start is issued."""
    user = update.effective_user
    welcome_text = f"""
🔥 Welcome to the Firebase & API Key Extractor Bot, {user.first_name}!

🤖 I can extract Firebase configurations, API keys, and other secrets from APK files.

📤 How to use me:
1. Send me a single APK file - I'll analyze it immediately
2. Send me multiple APKs at once (up to 20) - I'll process them in bulk
3. You can also send APKs in a ZIP file

🔧 Commands:
/start - Show this message
/help - Show help
/extract - Extract from last APK(s) again
/check_security - Check Firebase security
/bulk_status - Check bulk processing status

⚠️ Disclaimer: Use only on APKs you own or have permission to test!
"""
    await update.message.reply_text(welcome_text)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send help message."""
    help_text = """
📖 **How to Use This Bot**

**Single APK:**
1. Send any `.apk` file
2. I'll analyze and extract Firebase configs
3. You'll get a detailed report

**Bulk APK (Up to 20):**
1. Send multiple APK files in one message
2. I'll process them all
3. You'll get a summary report for each

**ZIP File:**
1. Send a ZIP containing APK files
2. I'll extract and process all of them

**What I Extract:**
🔥 Firebase URLs
🔑 API Keys (Google, Firebase)
📋 Project IDs
📱 App IDs
🗄️ Storage Buckets
📦 All other found secrets

**Commands:**
/extract - Re-run extraction on last APK(s)
/check_security - Run security check on found Firebase URLs
/bulk_status - Check bulk processing status
/start - Show welcome message
/help - Show this help

**⚠️ Important:**
- Max 20 APKs per batch
- Files are deleted after analysis
- Use responsibly!
"""
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def handle_documents(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle single or multiple document uploads"""
    user_id = update.effective_user.id
    message = update.message

    # Check if there are multiple documents
    documents = []
    if message.document:
        documents = [message.document]

    if not documents:
        await update.message.reply_text(
            "❌ Please send one or more APK files (max 20)."
        )
        return

    # Filter only APK files and ZIP files
    apks = []
    zip_files = []

    for doc in documents:
        if doc.file_name.endswith('.apk'):
            apks.append(doc)
        elif doc.file_name.endswith('.zip'):
            zip_files.append(doc)

    # Handle ZIP files
    if zip_files:
        await handle_zip_files(update, context, zip_files)
        return

    if not apks:
        await update.message.reply_text(
            "❌ No APK files found. Please send `.apk` files or a `.zip` containing APKs."
        )
        return

    if len(apks) > 20:
        await update.message.reply_text(
            f"❌ Too many APKs! Max 20 allowed. You sent {len(apks)}."
        )
        return

    # Start processing
    await update.message.reply_text(
        f"📥 Received {len(apks)} APK(s). Starting analysis...\n"
        f"⏳ This may take a few minutes."
    )

    # Process each APK
    results = []
    for i, doc in enumerate(apks, 1):
        status_msg = await update.message.reply_text(
            f"⏳ Processing [{i}/{len(apks)}]: `{doc.file_name}`",
            parse_mode='Markdown'
        )

        try:
            apk_path = os.path.join(DOWNLOAD_DIR, doc.file_name)
            file = await context.bot.get_file(doc.file_id)
            await file.download_to_drive(apk_path)

            # Extract
            configs = get_firebase_configs_only(apk_path)
            total_found = sum(len(v) for v in configs.values())

            results.append({
                "name": doc.file_name,
                "configs": configs,
                "total_found": total_found,
                "path": apk_path
            })

            await status_msg.edit_text(
                f"✅ [{i}/{len(apks)}] `{doc.file_name}` complete! Found {total_found} items."
            )

        except Exception as e:
            logger.error(f"Error processing {doc.file_name}: {e}")
            await status_msg.edit_text(
                f"❌ [{i}/{len(apks)}] `{doc.file_name}` failed: {str(e)[:50]}"
            )
            results.append({
                "name": doc.file_name,
                "error": str(e),
                "total_found": 0
            })

    # Generate summary
    await generate_bulk_summary(update, context, results, user_id)


async def handle_zip_files(update: Update, context: ContextTypes.DEFAULT_TYPE, zip_documents):
    """Handle ZIP files containing multiple APKs"""
    for zip_doc in zip_documents:
        await update.message.reply_text(
            f"📥 Processing ZIP: `{zip_doc.file_name}`",
            parse_mode='Markdown'
        )

        # Download ZIP
        zip_path = os.path.join(TEMP_APK_DIR, zip_doc.file_name)
        file = await context.bot.get_file(zip_doc.file_id)
        await file.download_to_drive(zip_path)

        # Extract APKs from ZIP
        apk_paths = []
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                for file_info in z.filelist:
                    if file_info.filename.endswith('.apk'):
                        extracted_path = os.path.join(TEMP_APK_DIR, os.path.basename(file_info.filename))
                        with open(extracted_path, 'wb') as f:
                            f.write(z.read(file_info.filename))
                        apk_paths.append(extracted_path)

            if not apk_paths:
                await update.message.reply_text("❌ No APK files found in ZIP.")
                os.remove(zip_path)
                return

            if len(apk_paths) > 20:
                await update.message.reply_text(
                    f"❌ ZIP contains {len(apk_paths)} APKs. Max 20 allowed."
                )
                os.remove(zip_path)
                return

            await update.message.reply_text(
                f"📦 Found {len(apk_paths)} APK(s) in ZIP. Processing..."
            )

            # Process all APKs
            results = []
            for i, apk_path in enumerate(apk_paths, 1):
                try:
                    configs = get_firebase_configs_only(apk_path)
                    total_found = sum(len(v) for v in configs.values())

                    results.append({
                        "name": Path(apk_path).name,
                        "configs": configs,
                        "total_found": total_found,
                        "path": apk_path
                    })

                    await update.message.reply_text(
                        f"✅ [{i}/{len(apk_paths)}] `{Path(apk_path).name}` - Found {total_found} items."
                    )

                except Exception as e:
                    results.append({
                        "name": Path(apk_path).name,
                        "error": str(e),
                        "total_found": 0
                    })

            # Generate summary
            await generate_bulk_summary(update, context, results, update.effective_user.id)

            # Clean up
            os.remove(zip_path)
            for p in apk_paths:
                try:
                    os.remove(p)
                except:
                    pass

        except Exception as e:
            await update.message.reply_text(f"❌ Error processing ZIP: {str(e)}")


async def generate_bulk_summary(update: Update, context: ContextTypes.DEFAULT_TYPE, results: List[Dict], user_id: int):
    """Generate summary for bulk APK processing"""
    lines = []
    lines.append("=" * 60)
    lines.append("  📊 BULK APK EXTRACTION SUMMARY")
    lines.append("=" * 60)

    total_found = 0
    success_count = 0

    for result in results:
        name = result.get('name', 'Unknown')
        found = result.get('total_found', 0)
        total_found += found
        if found > 0:
            success_count += 1
            lines.append(f"\n✅ {name}: {found} items found")
        else:
            error = result.get('error')
            if error:
                lines.append(f"\n❌ {name}: Error - {error[:50]}")
            else:
                lines.append(f"\n⚪ {name}: No Firebase configs found")

    lines.append("\n" + "-" * 60)
    lines.append(f"📊 Total APKs: {len(results)}")
    lines.append(f"✅ Successful: {success_count}")
    lines.append(f"📦 Total secrets found: {total_found}")
    lines.append("=" * 60)

    summary = '\n'.join(lines)

    # Store results for later use
    user_data_store[user_id] = {
        "bulk_results": results,
        "summary": summary,
        "timestamp": datetime.now().isoformat()
    }

    # Send summary
    await update.message.reply_text(
        f"✅ **Bulk Analysis Complete!**\n\n```\n{summary}\n```",
        parse_mode='Markdown'
    )

    # Send individual reports for each APK with findings
    for result in results:
        if result.get('total_found', 0) > 0:
            configs = result.get('configs', {})
            report = generate_summary_report_from_configs(result.get('name'), configs)
            await update.message.reply_text(
                f"📄 **{result.get('name')}**\n```\n{report[:3000]}\n```",
                parse_mode='Markdown'
            )


def generate_summary_report_from_configs(name: str, configs: Dict) -> str:
    """Generate report from configs dict"""
    lines = []
    lines.append(f"📱 APK: {name}")
    lines.append("-" * 40)

    urls = configs.get('firebase_urls', [])
    if urls:
        lines.append(f"\n🔥 Firebase URLs ({len(urls)}):")
        for url in urls:
            lines.append(f"   {url}")

    keys = configs.get('api_keys', [])
    if keys:
        lines.append(f"\n🔑 API Keys ({len(keys)}):")
        for key in keys:
            lines.append(f"   {key[:20]}...")

    projects = configs.get('project_ids', [])
    if projects:
        lines.append(f"\n📋 Project IDs ({len(projects)}):")
        for proj in projects:
            lines.append(f"   {proj}")

    return '\n'.join(lines)


async def bulk_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check bulk processing status"""
    user_id = update.effective_user.id

    if user_id not in user_data_store:
        await update.message.reply_text("❌ No bulk processing history found.")
        return

    data = user_data_store[user_id]
    summary = data.get('summary', 'No summary available')
    timestamp = data.get('timestamp', 'Unknown')

    await update.message.reply_text(
        f"📊 **Last Bulk Processing**\n📅 {timestamp}\n\n```\n{summary}\n```",
        parse_mode='Markdown'
    )


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle unknown commands."""
    await update.message.reply_text(
        "❌ Unknown command. Use /help to see available commands."
    )


# ==================== Main Application ====================

def setup_application():
    """Setup the bot application."""
    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("bulk_status", bulk_status_command))

    # Handle documents (single or multiple)
    application.add_handler(MessageHandler(filters.Document.ALL, handle_documents))

    application.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    return application


# ==================== Start the Bot ====================

if __name__ == "__main__":
    print("🤖 Starting Firebase Extractor Bot (Polling mode)...")
    
    # Setup the bot application
    bot_app = setup_application()
    
    # Run Flask web server in a separate thread for Render health checks
    def run_flask():
        app.run(host='0.0.0.0', port=PORT, debug=False, use_reloader=False)
    
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    print(f"✅ Flask web server running on port {PORT}")
    
    # Start the Telegram bot (polling mode)
    bot_app.run_polling(allowed_updates=Update.ALL_TYPES)
