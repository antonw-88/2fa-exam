# -*- coding: utf-8 -*-
# This is a sample Python script.
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os
import time
import threading
import subprocess

user_registry_location = "/home/anton/2fa-prototype-data/userRegistry.txt"
user_2fa_logging_location = "/home/anton/2fa-prototype-data/2faLogs.txt"
user_accessed_2fa = [0] * 100 # Sets user limit for tool
scan_for_logout_frequency = 5 # Sets how often the tool should scan for user log in/log out

def menu_print():
    print("Welcome to the 2fa honeytoken prototype, enter your choice from the menu below:\n"
          "1. Start tracking honeytokens\n"
          "2. Add new user\n"
          "3. Exit program\n\n")
    menu_choice = input();
    return menu_choice;


# Add a honeytoken to a specified user
def add_user():
    user_regi = open(user_registry_location, "a")
    print("Enter user's username:")
    user_name = input()
    print("Enter location for user's honeytoken(fullpath hardcoded):")
    honey_location = input()
    if not os.path.exists("\"" + honey_location + "\""):
        honeytoken = open(honey_location, "w+")
        honeytoken.close()
    chown_command = "chown " + user_name + " " + honey_location
    os.system(chown_command)
    chmod_command = "chmod 700 " + honey_location
    os.system(chmod_command)
    user_regi.write(user_name + " " + honey_location + "\n")
    user_regi.close()

#Notification function
def notify(user_name):
	userID = subprocess.run(['id', '-u', os.environ['SUDO_USER']],
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				check=True).stdout.decode("utf-8").replace('\n', '')

	subprocess.run(['sudo', '-u', os.environ['SUDO_USER'], 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{}/bus'.format(userID),
				'notify-send', '-u', 'critical', 'Critical Intrusion Alert. Potentially Masquerading User= ' + user_name],
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				check=True)

# Timelimit
def time_limit(honeytoken_array, user_names_array, i):
    countdown = 0
    while countdown < 30:  # Countdown 30 seconds
        time.sleep(1)
        countdown += 1
        print("\nUser: " + user_names_array[i])
        print("Countdown until 30, then access to 2fa honeytoken is removed"
              "(user info is also logged, open processes are logged, realtime warning sent to admin):")
        print(countdown)
        # Only runs if the user does not access the 2fa token within 30 seconds
        if countdown >= 30 and user_accessed_2fa[i] != 1:  # If did not access token within 30 seconds, remove user's access to 2fa honeytoken
            lock_2fa_token_command = "chmod 000 " + honeytoken_array[i]
            os.system(lock_2fa_token_command)
            lock_2fa_token_chown_command = "chown root " + honeytoken_array[i]
            os.system(lock_2fa_token_chown_command)
            # Log user's data to file that stores info about user(username, IP, etc.)
            # when 2fa is not accessed within time-limit
            user_2fa_logs = open(user_2fa_logging_location, "a")
            user_2fa_logs.write("POTENTIALLY MASQUERADING USER: " + user_names_array[i])
            result = subprocess.run(['w', '-x', '|', 'grep', user_names_array[i]], capture_output=True,
                                    text=True, shell=True).stdout
            user_2fa_logs.write(result)
            user_2fa_logs.write("\n")
            # Get user's open processes and write them to the log
           # result = subprocess.run(['sudo', 'top','|', 'grep', 'anton'], capture_output=True,
            #                        text=True, shell=True).stdout
            result = subprocess.run(['ps', '-u', user_names_array[i]], capture_output=True,
                                     text=True).stdout
            user_2fa_logs.write(result)
            user_2fa_logs.write("\n ------------------------------------ \n")
            user_2fa_logs.close()
            notify(user_names_array[i])
        # If user accesses the token, the time_limit control loop is broken
        if user_accessed_2fa[i] == 1:
            break


# Monitor that user is still logged in, else remove access to working folder
def check_if_logged_out():
    usr_regi = open(user_registry_location, "r")
    lines = usr_regi.readlines()
    user_names_array = [] # Stores the username for all user's with honeytokens
    honeytoken_array = [] # Stores the location of each user's honeytoken
    access_array = []  # stores data for controlling that user accesses 2fa honeytoken within timelimit

    i = 0
    for line in lines:  # Add each user's username to name list
        user_names_array.append(line.split()[0])
        i += 1

    i = 0
    for line in lines:  # Add each user's honeytoken to token list
        honeytoken_array.append(line.split()[1])
        i += 1

    # Makes sure that threads controlling the time limit:
    # 1. do not run as duplicates for single user
    # 2. access to 2fa honeytoken is regulated correctly
    user_logged_in_array = [0] * len(user_names_array)

    while 0 == 0:  # Should run indefinitely - will scan for active users once every 5 seconds
        i = 0
        time.sleep(scan_for_logout_frequency)
        print("\n")
        while i < len(user_names_array):  # Run a check every 5 secs, to see if user is logged in
            bash_command = "w | grep " + user_names_array[i]
            return_value = os.system(bash_command)

            # Start countdown when user logs in
            if return_value == 0 and user_logged_in_array[i] == 0:
                user_logged_in_array[i] = 1
                # The usecase for the lock command for the token, is that an intruder doesn't find the token after looking around for a while
                # If he/she does so, the token is locked anyway(denying access to the protected folder)
                # If authorized user forgets to access within 30 seconds, they can relog and access token since this unlocks it
                unlock_2fa_token_chmod_command = "chmod 700 " + honeytoken_array[i]
                os.system(unlock_2fa_token_chmod_command)
                unlock_2fa_token_chown_command = "chown " + user_names_array[i] + " " + honeytoken_array[i]
                os.system(unlock_2fa_token_chown_command)
                #Relock folder since the chmod will be picked up by inotify(thereby unlocking the folder)
                relock_folder_command = "chmod 000 /usr/local/real" + user_names_array[i] + " | chown root /usr/local/real" + user_names_array[i]
                os.system(relock_folder_command)

                check_access_command = "ls -ld /usr/local/real" + user_names_array[i] + " | grep " + user_names_array[i]
                return_value = os.system(check_access_command)
                # Set up thread for countdown of timelimit
                try:
                   time_limit_thread = threading.Thread(target=time_limit, args=(honeytoken_array, user_names_array, i))
                   time_limit_thread.daemon = True
                   time_limit_thread.start()
                except:
                   print("Error: unable to start time_limit monitoring thread")

            # Remove access when user no longer logged in
            if return_value != 0:
                # set control so that if user relogs, the 2fa honeytoken permissions are reset
                user_logged_in_array[i] = 0
                user_accessed_2fa[i] = 0
                logout_command = "chown root /usr/local/real" + user_names_array[i]
                os.system(logout_command)
                os.system("chmod 000 /usr/local/real"
                      + user_names_array[i])
                delete_bash_history = "rm /home/" + user_names_array[i] + "/.bash_history"
                if os.path.exists("/home/" + user_names_array[i] + "/.bash_history"):
                    os.system(delete_bash_history)
            i += 1


def monitor_honeytoken(token_array, index):
    # run as infinite
    while 0 == 0:
        honeylocation_index = 1
        username_index = 0
        bash_command = "inotifywait -e open -e access " + token_array[index].split()[honeylocation_index]
        access_check = os.system(bash_command)
        if access_check == 0:
             os.system("chown " + token_array[index].split()[username_index] + " /usr/local/real"
                      + token_array[index].split()[username_index])
             os.system("chmod 700 /usr/local/real"
                      + token_array[index].split()[username_index])
             user_accessed_2fa[index] = 1


# Initiate the monitoring of 2fa honeytokens
def token_2fa_init():
    usr_regi = open(user_registry_location, "r");
    lines = usr_regi.readlines()
    token_array = []
    i = 0
    for line in lines:  # Add each honeytoken location and username list, and create thread for each entry
        token_array.append(line)
        try:
            monitoring_thread = threading.Thread(target=monitor_honeytoken, args=(token_array, i))
            monitoring_thread.daemon=True
            monitoring_thread.start()
        except:
            print ("Error: unable to start honeytoken monitoring thread")
        i += 1

# Main
if __name__ == '__main__':
    while 0 == 0:
        menu_choice = menu_print()
        if menu_choice == "1":
            token_2fa_init()
            check_if_logged_out()
        elif menu_choice == "2":
            add_user()
        elif menu_choice == "3":  # Exit program
            print("Exiting program.")
            quit()

