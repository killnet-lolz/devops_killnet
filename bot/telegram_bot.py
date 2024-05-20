import logging
import re
import paramiko
import os
from dotenv import load_dotenv
from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler
import psycopg2
from psycopg2 import Error
load_dotenv()
TOKEN = os.getenv('TOKEN')

# Подключаем логирование
logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)

import paramiko

class LinuxMonitor:
    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.client = None

    def connect(self):
        """Устанавливает SSH-подключение к серверу."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname=self.hostname, username=self.username, password=self.password, port=self.port)

    def execute_command(self, command, ignore_errors=False):
        """Выполняет команду на сервере и возвращает вывод.
        
        Args:
            command (str): Команда для выполнения.
            ignore_errors (bool, optional): Игнорировать ошибки. Defaults to False.
        """
        stdin, stdout, stderr = self.client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        if not ignore_errors and error:
            raise Exception(error)
        return output

    def get_release(self):
        """Получает информацию о релизе."""
        return self.execute_command("cat /etc/*-release")

    def get_uname(self):
        """Получает информацию об архитектуре процессора, имени хоста и версии ядра."""
        return self.execute_command("uname -a")

    def get_uptime(self):
        """Получает время работы системы."""
        return self.execute_command("uptime")

    def get_df(self):
        """Получает информацию о состоянии файловой системы."""
        return self.execute_command("df -h")

    def get_free(self):
        """Получает информацию о состоянии оперативной памяти."""
        return self.execute_command("free -h")

    def get_mpstat(self):
        """Получает информацию о производительности системы."""
        return self.execute_command("mpstat")

    def get_w(self):
        """Получает информацию о работающих пользователях."""
        return self.execute_command("w")

    def get_auths(self):
        """Получает последние 10 входов в систему."""
        return self.execute_command("last -n 10")

    def get_critical(self):
        """Получает последние 5 критических событий."""
        return self.execute_command("journalctl -p 2 -n 5")

    def get_ps(self):
        """Получает заголовок информации о запущенных процессах."""
        return self.execute_command("ps")

    def get_ss(self):
        """Получает информацию об используемых портах."""
        return self.execute_command("ss -tulwn")

    def get_apt_list(self, package_name=None):
        """Получает информацию об установленных пакетах."""
        if package_name is None or package_name.lower() == "all":
            command = "apt list --installed"
        else:
            command = f"apt list {package_name}"
        return self.execute_command(command, ignore_errors=True)

    def get_services(self):
        """Получает информацию о запущенных сервисах."""
        return self.execute_command("systemctl list-units --type=service --state=running")

def handle_command(update: Update, context):
    """Обработчик команд, отправляющий ответ через update.message.reply_text."""
    command = update.message.text

    if command in [
        "/get_release", "/get_uname", "/get_uptime", "/get_df", "/get_free",
        "/get_mpstat", "/get_w", "/get_auths", "/get_critical", "/get_ps",
        "/get_ss", "/get_apt_list", "/get_services"
    ]:
        hostname = os.getenv('RM_HOST')
        port = os.getenv('RM_PORT')
        username = os.getenv('RM_USER')
        password = os.getenv('RM_PASSWORD')

        monitor = LinuxMonitor(hostname, port, username, password)
        monitor.connect()

        try:
            if command == "/get_release":
                result = monitor.get_release()
            elif command == "/get_uname":
                result = monitor.get_uname()
            elif command == "/get_uptime":
                result = monitor.get_uptime()
            elif command == "/get_df":
                result = monitor.get_df()
            elif command == "/get_free":
                result = monitor.get_free()
            elif command == "/get_mpstat":
                result = monitor.get_mpstat()
            elif command == "/get_w":
                result = monitor.get_w()
            elif command == "/get_auths":
                result = monitor.get_auths()
            elif command == "/get_critical":
                result = monitor.get_critical()
            elif command == "/get_ps":
                result = monitor.get_ps()
            elif command == "/get_ss":
                result = monitor.get_ss()
            elif command == "/get_services":
                result = monitor.get_services()
            if len(result) > 4096:
                # Create a temporary text file
                with open("temp_result.txt", "w") as f:
                    f.write(result)

                # Send the text file
                with open("temp_result.txt", "rb") as f:
                    update.message.reply_document(document=f)

                # Delete the temporary file
                os.remove("temp_result.txt")
            else:
                update.message.reply_text(result)
        except Exception as e:
            update.message.reply_text(f"Ошибка: {e}")


def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!')


def helpCommand(update: Update, context):
    update.message.reply_text('Help!')


def find_phone_numbers_command(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')

    return 'find_phone_number'

def find_emails_command(update: Update, context):
    update.message.reply_text('Введите текст для поиска email: ')

    return 'find_email'

def verify_password_command(update: Update, context):
    update.message.reply_text('Введите пароль для проверки: ')

    return 'verify_password'


def find_emails(update: Update, context):
    """Ищет email-адреса в тексте и выводит их, удаляя дубликаты."""
    text = update.message.text
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    emails = re.findall(email_pattern, text)

    # Удаление дубликатов
    unique_emails = []
    for email in emails:
        if email not in unique_emails:
            unique_emails.append(email)

    result = ""
    for i, email in enumerate(unique_emails, start=1):
        result += f'{i}. {email}\n'

    if unique_emails:
        update.message.reply_text(f"{result}")
        update.message.reply_text('Хотите сохранить найденные email адреса в базе данных? (Да/Нет)')
    else:
        update.message.reply_text("Email-адреса не найдены.")

    context.user_data['emails'] = unique_emails  # Сохраняем найденные email-адреса в контексте

    return 'save_emails'

def save_emails(update: Update, context):
    user_input = update.message.text.lower()
    emails = context.user_data.get('emails')

    if user_input == 'да' and emails:
        try:
            conn = connect_to_postgres()
            if conn:
                cursor = conn.cursor()
                for email in emails:
                    cursor.execute("INSERT INTO emails (email) VALUES (%s)", (email,))
                conn.commit()
                conn.close()
                update.message.reply_text('Email адреса успешно сохранены в базе данных.')
            else:
                update.message.reply_text('Не удалось подключиться к базе данных.')
        except psycopg2.Error as e:
            logger.error("Ошибка при сохранении email адресов: %s", e)
            update.message.reply_text('При сохранении email адресов произошла ошибка.')
    else:
        update.message.reply_text('Email адреса не сохранены.')

    return ConversationHandler.END

def find_phone_numbers(update: Update, context):
    """Ищет номера телефонов в тексте и выводит их с нумерацией и форматированием, 
    удаляя дубликаты."""
    user_input = update.message.text
    phone_num_regex = re.compile(r"(?:8|\+7)[\s\-]?(?:\(\d{3}\)|\d{3})[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")
    phone_number_list = phone_num_regex.findall(user_input)

    if not phone_number_list:
        update.message.reply_text("Телефонные номера не найдены.")
        return ConversationHandler.END

    # Форматирование и нумерация номеров, удаление дубликатов
    save_numbers = []
    formatted_numbers = []
    for i, num in enumerate(phone_number_list, 1):
        # Удаление пробелов и дефисов и скобок
        clean_num = re.sub(r"\s|-|\(|\)", "", num)
        # Добавление кода страны, если его нет
        if not clean_num.startswith("+"):
            clean_num = clean_num[1:]
            clean_num = "+7" + clean_num
        # Проверка на наличие номера в списке
        if clean_num not in save_numbers:
            save_numbers.append(f"{clean_num}")
            formatted_numbers.append(f"{i}. {clean_num}")

    update.message.reply_text("\n".join(formatted_numbers))
    update.message.reply_text('Хотите сохранить найденные номера телефонов в базе данных? (Да/Нет)')

    context.user_data['phone_numbers'] = save_numbers
    return 'save_phone_numbers'

def save_phone_numbers(update: Update, context):
    user_input = update.message.text.lower()
    phone_numbers = context.user_data.get('phone_numbers')

    if user_input == 'да' and phone_numbers:
        try:
            conn = connect_to_postgres()
            if conn:
                cursor = conn.cursor()
                for phone_number in phone_numbers:
                    cursor.execute("INSERT INTO phone_numbers (phone_number) VALUES (%s)", (phone_number,))
                conn.commit()
                conn.close()
                update.message.reply_text('Номера телефонов успешно сохранены в базе данных.')
            else:
                update.message.reply_text('Не удалось подключиться к базе данных.')
        except psycopg2.Error as e:
            logger.error("Ошибка при сохранении номеров телефонов: %s", e)
            update.message.reply_text('При сохранении номеров телефонов произошла ошибка.')
    else:
        update.message.reply_text('Номера телефонов не сохранены.')

    return ConversationHandler.END

def verify_password(update: Update, context):
    text = update.message.text
    password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$"
    passwords = re.findall(password_pattern, text)

    if passwords:
        update.message.reply_text("Пароль сложный")
    else:
        update.message.reply_text("Пароль простой")
    return ConversationHandler.END  # Завершаем работу обработчика диалога


def echo(update: Update, context):
    update.message.reply_text(update.message.text)

CHOOSING, TYPING_REPLY = range(2)

def get_apt_list_command(update: Update, context) -> int:
    """Запускает диалог для получения списка пакетов."""
    update.message.reply_text(
        "Выберите действие:\n"
        "1. Вывести все пакеты\n"
        "2. Найти информацию о пакете",
        reply_markup=ForceReply(selective=True),
    )
    return CHOOSING

def get_apt_choice(update: Update, context) -> int:
    """Обрабатывает выбор пользователя и выполняет соответствующее действие."""
    choice = update.message.text

    if choice == '1':
        # Вывести все пакеты
        hostname = os.getenv('RM_HOST')
        port = os.getenv('RM_PORT')
        username = os.getenv('RM_USER')
        password = os.getenv('RM_PASSWORD')

        monitor = LinuxMonitor(hostname, port, username, password)
        monitor.connect()
        try:
            result = monitor.get_apt_list()  # Вывод всех пакетов
            if len(result) > 4096:
                # Create a temporary text file
                with open("temp_result.txt", "w") as f:
                    f.write(result)

                # Send the text file
                with open("temp_result.txt", "rb") as f:
                    update.message.reply_document(document=f)

                # Delete the temporary file
                os.remove("temp_result.txt")
            else:
                update.message.reply_text(result)
        except Exception as e:
            update.message.reply_text(f"Ошибка: {e}")

        return ConversationHandler.END  # Завершаем диалог

    elif choice == '2':
        # Запросить название пакета
        update.message.reply_text("Введите название пакета:")
        return TYPING_REPLY

    else:
        update.message.reply_text("Неверный выбор. Пожалуйста, введите 1 или 2.")
        return CHOOSING  # Остаемся в состоянии выбора

def get_apt_info(update: Update, context) -> int:
    """Получает название пакета и выводит информацию о нем."""
    package_name = update.message.text

    hostname = os.getenv('RM_HOST')
    port = os.getenv('RM_PORT')
    username = os.getenv('RM_USER')
    password = os.getenv('RM_PASSWORD')

    monitor = LinuxMonitor(hostname, port, username, password)
    monitor.connect()
    try:
        result = monitor.get_apt_list(package_name)  # Вывод информации о конкретном пакете
        if len(result) > 4096:
            # Create a temporary text file
            with open("temp_result.txt", "w") as f:
                f.write(result)

            # Send the text file
            with open("temp_result.txt", "rb") as f:
                update.message.reply_document(document=f)

            # Delete the temporary file
            os.remove("temp_result.txt")
        else:
            update.message.reply_text(result)
    except Exception as e:
        update.message.reply_text(f"Ошибка: {e}")

    return ConversationHandler.END  # Завершаем диалог

def get_repl_logs(update: Update, context):
    """
    Получает логи репликации PostgreSQL и отправляет их пользователю.
    """
    hostname = os.getenv('RM_HOST')
    port = os.getenv('RM_PORT')
    username = os.getenv('RM_USER')
    password = os.getenv('RM_PASSWORD')

    monitor = LinuxMonitor(hostname, port, username, password)
    monitor.connect()
    logs=monitor.execute_command(f'echo {password} | sudo -S docker logs db 2>&1 | grep "replica" | tail -n20')
    # Обработка логов
    if logs:
        if len(logs) > 4096:
            # Create a temporary text file
            with open("temp_result.txt", "w") as f:
                f.write(logs)

                # Send the text file
            with open("temp_result.txt", "rb") as f:
                update.message.reply_document(document=f)

            # Delete the temporary file
            os.remove("temp_result.txt")
        else:
            update.message.reply_text(logs)
    else:
        update.message.reply_text("Логи репликации не найдены.")
def connect_to_postgres():
    """
    Подключается к базе данных PostgreSQL и возвращает объект соединения.

    Returns:
        psycopg2.connection: Объект соединения с PostgreSQL.
        None: Если подключение не удалось.
    """
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_DATABASE"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT")
        )
        return conn
    except psycopg2.Error as e:
        logger.error(f"Ошибка подключения к PostgreSQL: {e}")
        return None

def get_phone_numbers(update: Update, context):
    """
    Обрабатывает команду '/get_phone_numbers' в Telegram-боте, получая и отправляя 
    номера телефонов из таблицы 'phone_numbers'.
    """
    try:
        with connect_to_postgres() as conn:
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT phone_number FROM phone_numbers;")
                    phone_numbers = cursor.fetchall()
                    if phone_numbers:
                        update.message.reply_text("\n".join(number[0] for number in phone_numbers))
                    else:
                        update.message.reply_text("Номера не найдены.")
            else:
                update.message.reply_text("Не удается подключиться к базе данных.")
    except psycopg2.Error as e:
        logging.error("Ошибка при получении номеров телефонов: %s", e)
        update.message.reply_text("При загрузке номеров телефонов произошла ошибка.")

def get_emails(update: Update, context):
    """
    Обрабатывает команду '/get_emails' в Telegram-боте, получая и отправляя 
    адреса электронной почты из таблицы 'emails'.
    """
    try:
        with connect_to_postgres() as conn:
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT email FROM emails;")
                    emails = cursor.fetchall()
                    if emails:
                        update.message.reply_text("\n".join(email[0] for email in emails))
                    else:
                        update.message.reply_text("Email addresses not found.")
            else:
                update.message.reply_text("Не удается подключиться к базе данных.")
    except psycopg2.Error as e:
        logging.error("Ошибка при получении электронных писем: %s", e)
        update.message.reply_text("При загрузке адресов электронной почты произошла ошибка.")


def main():
    updater = Updater(TOKEN, use_context=True)

    # Получаем диспетчер для регистрации обработчиков
    dp = updater.dispatcher

    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('find_phone_number', find_phone_numbers_command)],
        states={
            'find_phone_number': [MessageHandler(Filters.text & ~Filters.command, find_phone_numbers)],
            'save_phone_numbers': [MessageHandler(Filters.text & ~Filters.command, save_phone_numbers)]
        },
        fallbacks=[]
    )
    convHandlerFindEmails = ConversationHandler(
        entry_points=[CommandHandler('find_email', find_emails_command)],
        states={
            'find_email': [MessageHandler(Filters.text & ~Filters.command, find_emails)],
            'save_emails': [MessageHandler(Filters.text & ~Filters.command, save_emails)]
        },
        fallbacks=[]
    )

    # Обработчик диалога
    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler("verify_password", verify_password_command)],
        states={
            'verify_password': [MessageHandler(Filters.text & ~Filters.command, verify_password)],
        },
        fallbacks=[]
    )
    # Обработчик диалога для /get_apt_list
    convHandler_get_apt_list = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={
            CHOOSING: [MessageHandler(Filters.text & ~Filters.command, get_apt_choice)],
            TYPING_REPLY: [MessageHandler(Filters.text & ~Filters.command, get_apt_info)]
        },
        fallbacks=[],
    )

    # Регистрируем обработчики команд
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmails)
    dp.add_handler(convHandlerVerifyPassword)
    dp.add_handler(convHandler_get_apt_list)
    dp.add_handler(CommandHandler("get_release", handle_command))
    dp.add_handler(CommandHandler("get_uname", handle_command))
    dp.add_handler(CommandHandler("get_uptime", handle_command))
    dp.add_handler(CommandHandler("get_df", handle_command))
    dp.add_handler(CommandHandler("get_free", handle_command))
    dp.add_handler(CommandHandler("get_mpstat", handle_command))
    dp.add_handler(CommandHandler("get_w", handle_command))
    dp.add_handler(CommandHandler("get_auths", handle_command))
    dp.add_handler(CommandHandler("get_critical", handle_command))
    dp.add_handler(CommandHandler("get_ps", handle_command))
    dp.add_handler(CommandHandler("get_ss", handle_command))
    dp.add_handler(CommandHandler("get_apt_list", handle_command))
    dp.add_handler(CommandHandler("get_services", handle_command))
    dp.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))




    # Регистрируем обработчик текстовых сообщений
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))

    # Запускаем бота
    updater.start_polling()

    # Останавливаем бота при нажатии Ctrl+C
    updater.idle()


if __name__ == '__main__':
    main()
