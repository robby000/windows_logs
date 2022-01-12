# This program is a Windows logs analyser. It has three main objectives:
# 1. To save the logs in an organised way to a CSV file.
# 2. Create alerts for serious security logs.
# 3. Can continuously check every half an hour for new logs add them to the CSV file and create alerts.

# The three log types accessed by this program are Application, Security and System. Each of them are organised into
# different files according to their type:
# Application is split into two files, one for regular events while the other is for error events which constitutes most
# of these events.
# Security events are split into three files according to their severity (This information was sourced from Microsoft's
# website). The program reads three files which contain lists of the events including their definition and creates a
# dictionary from them. These definitions are also displayed in the alerts created.
# System events are split into three files according to their types: 'Information Events', 'Error Events' and 'Warning
# events'.

# This program must be run as an administrator.

# The 'pywin32' library must be installed.

########################################################################################################################
# Imports
import win32evtlog
import ctypes
import os
from os import getcwd
from time import sleep
import win32api
import csv
from datetime import datetime, timedelta

########################################################################################################################
# Declare Constants, variables and lists

# CSV File Names
high_csv = "Security_Events_High"
medium_csv = "Security_Events_Medium"
low_csv = "Security_Events_Low"
application = "Application_Events"
application_error = "Application_Error_Events"
system_info = "System_Information_Events"
system_warning = "System_Warning_Events"
system_error = "System_Error_Events"

# Generic file header list for CSV files
FILE_HEADER = ["Event ID", "Event Category", "Event Source Name", "Event Type", "Event Date/ Time",
               "Event String insert", "Event Explainer (Security Only)"]

# Security text file names list
FILENAMES = ["security_events_high.txt", "security_events_medium.txt", "security_events_low.txt"]

# Create empty list for event data
low_list = []
medium_list = []
high_list = []
application_list = []
application_error_list = []
system_info_list = []
system_error_list = []
system_warning_list = []

location = getcwd()  # Create relative path for files

time_running_pro = 0  # Variable to count the amount of times the program is run
########################################################################################################################
# Importing data from external files

# Create dictionaries from security events directories in external files

# Declare dictionaries
security_events_high = {}
security_events_medium = {}
security_events_low = {}

try:
    for file in FILENAMES:
        with open(file) as f:
            for line in f:
                (key, val) = line.split(":")
                if file == "security_events_high.txt":
                    security_events_high[int(key)] = val
                    for key, value in security_events_high.items():
                        security_events_high[key] = value.rstrip()
                elif file == "security_events_medium.txt":
                    security_events_medium[int(key)] = val
                    for key, value in security_events_medium.items():
                        security_events_medium[key] = value.rstrip()
                elif file == "security_events_low.txt":
                    security_events_low[int(key)] = val
                    for key, value in security_events_low.items():
                        security_events_low[key] = value.rstrip()
except FileNotFoundError:  # Deal with file not found error
    print("Text file not found")
    exit(2)


########################################################################################################################

# Define Functions


# Check if program is running in Windows
def windows():
    if os.name == "nt":
        pass
    else:
        print("This program is strictly for Windows NT")
        exit(3)


def is_admin():
    # Check if user is administrator, returns 0 or 1
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except PermissionError:
        return False


# Check events if they were created within the last half an hour when running a continuous program
def check_time(time):
    last_half_hour_date_time = datetime.now() - timedelta(hours=0.5)
    global time_running_pro
    if program_type == "1":  # If only running once check all logs
        return True
    else:
        if time_running_pro < 1:  # First time running check all logs
            return True
        else:  # If running multiple times only check new logs from last 30 minutes
            if time >= last_half_hour_date_time:
                return True
            else:
                return False


# Create list of details
def event_detail_list(event):
    event_temp = [event.EventID, event.EventCategory, event.SourceName, event.EventType,
                  event.TimeGenerated, event.StringInserts]
    return event_temp


# Create list of details for security logs which has an extra row of data and variable
def event_detail_list_sec(event, dictionary):
    event_temp = [event.EventID, event.EventCategory, event.SourceName, event.EventType,
                  event.TimeGenerated, event.StringInserts, dictionary[event.EventID]]
    return event_temp


# Save logs to file, Sort out data and how it's saved in csv files and check errors that may arise.
def save_logs(file_name, data):
    csv_file = location + "\\" + file_name + ".csv"  # get file path
    # open the file in the write mode
    try:
        with open(csv_file, 'a', encoding='UTF8') as h:  # Use 'a' to append existing file with new data
            # create the csv writer
            csv_out = csv.writer(h)
            csv_out.writerow(FILE_HEADER)  # Write the header from constant list.
            for row in data:
                csv_out.writerows([row])  # Write the rest all the data.
    except PermissionError:  # This addresses the common error when the csv file was left open.
        print("Error: Please close the csv file.")
        exit(4)
    except FileNotFoundError:  # Wrong filename error.
        print("Error: File not found. Please recheck the csv file name and location.")
        exit(5)


# Check Application logs, create a list of lists of all the logs and sent it to the 'save_logs' function.
def check_application(logs):
    hand = win32evtlog.OpenEventLog("localhost", logs)  # Define server and logs type to access.
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ  # Define how to read logs.
    total = win32evtlog.GetNumberOfEventLogRecords(hand)  # Get the total number of logs.
    sum_evt = 0  # Declare variable
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)  # Declare the events
        sum_evt += len(events)  # Add the amount of events checking
        if events:
            for event in events:
                if check_time(event.TimeGenerated):  # Check when the events were created.
                    if event.SourceName == "Windows Error Reporting":  # Check event type.
                        application_error_list.append(event_detail_list(event))
                    else:
                        application_list.append(event_detail_list(event))  # Creates list of lists

        if sum_evt >= total:
            if not len(application_list) == 0:  # Check if events were found.
                save_logs(application, application_list)
            if not len(application_error_list) == 0:
                save_logs(application_error, application_error_list)
            break


# Check Security logs
def check_security(logs, severity_level):
    hand = win32evtlog.OpenEventLog("localhost", logs)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    sum_evt = 0
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        sum_evt += len(events)  # Add the amount of events checking
        if events:
            for event in events:
                if check_time(event.TimeGenerated):
                    if event.EventID in security_events_high:
                        #  Create win32 alerts for high events
                        win32api.MessageBox(0, 'Error Code: ' + str(event.EventID) + ' ' + str(
                            security_events_high[event.EventID]), 'High Risk Security event detected',
                                            0x00001000)
                        high_list.append(event_detail_list_sec(event, security_events_high))

                    elif event.EventID in security_events_medium:
                        if severity_level == "High":  # Create alerts if user requested.
                            win32api.MessageBox(0, 'Error Code: ' + str(event.EventID) + ' ' + str(
                                security_events_medium[event.EventID]), 'Medium Risk Security event detected',
                                                0x00001000)
                        medium_list.append(event_detail_list_sec(event, security_events_medium))

                    elif event.EventID in security_events_low:
                        if severity_level == "High":
                            win32api.MessageBox(0, 'Error Code: ' + str(event.EventID) + ' ' + str(
                                security_events_low[event.EventID]), 'Low Risk Security event detected',
                                                0x00001000)
                        low_list.append(event_detail_list_sec(event, security_events_low))

                    else:  # When event not found in dictionaries.
                        print("Security log not recognised. Here are the log details:")
                        print(event_detail_list(event))

        if sum_evt >= total:
            if not len(high_list) == 0:  # Check if any logs of this type were found
                save_logs(high_csv, high_list)

            if not len(medium_list) == 0:  # Check if any logs of this type were found
                save_logs(medium_csv, medium_list)

            if not len(low_list) == 0:  # Check if any logs of this type were found
                save_logs(low_csv, low_list)
            break


# Check System logs
def check_system(logs):
    hand = win32evtlog.OpenEventLog("localhost", logs)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    sum_evt = 0
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        sum_evt += len(events)  # Add the amount of events checking
        if events:
            for event in events:
                if check_time(event.TimeGenerated):
                    if event.EventType == 1:  # Sort by event type.
                        system_error_list.append(event_detail_list(event))
                    elif event.EventType == 2:
                        system_warning_list.append(event_detail_list(event))
                    elif event.EventType == 4:
                        system_info_list.append(event_detail_list(event))

            if sum_evt >= total:
                if not len(system_error_list) == 0:
                    save_logs(system_error, system_error_list)
                if not len(system_warning_list) == 0:
                    save_logs(system_warning, system_warning_list)
                if not len(system_info_list) == 0:
                    save_logs(system_info, system_info_list)
                break


# Create continuous loop
def continuous():
    global time_running_pro, low_list, medium_list, high_list, application_list, application_error_list, \
        system_info_list, system_error_list, system_warning_list
    if program_type == '1':  # Check if it was requested by user.
        print("The program has finished!")
        exit(6)
    elif program_type == '2':
        time_running_pro += 1  # Update amount of times the program has run
        # Clear all lists for every time program is rerun so that old logs are not rewritten
        low_list.clear()
        medium_list.clear()
        high_list.clear()
        application_list.clear()
        application_error_list.clear()
        system_info_list.clear()
        system_error_list.clear()
        system_warning_list.clear()
        print("The program will automatically run again in 30 minutes.")
        sleep(1800)  # Sleep for 30 minutes.


########################################################################################################################
# Check program is running in correct conditions

# Check OS
windows()

# Check if user is administrator
if is_admin():
    pass
else:
    print("Please run this program as administrator.")
    exit(7)

########################################################################################################################
# User Inputs

while True:
    program_type = input("This program can run as a one off to check all your logs or check your logs continuously "
                         "every 30 minutes. For a one off program enter '1' or for continuous running enter '2'. ")
    if program_type == '1':
        break
    elif program_type == '2':
        break
    else:
        print("Please enter '1' or '2'")

while True:
    log_input = input("Enter '1' for Application logs, '2' for Security logs, '3' for System logs. "
                      "Or if you want to check all the above logs enter 4. ")
    if log_input == '1':
        log_type = "Application"
        break
    elif log_input == '2':
        log_type = "Security"
        break
    elif log_input == '3':
        log_type = "System"
        break
    elif log_input == '4':
        log_type = "All"
        break
    else:
        print("Please enter a digit from 1-4")

severity_input = input("To get an alert for all security errors enter 1 otherwise enter any key")
if severity_input == '1':
    severity = "High"
else:
    severity = "Low"

########################################################################################################################

# Run correct function according to user input.
while True:

    if log_type == "Application":
        check_application(log_type)
    elif log_type == "Security":
        check_security(log_type, severity)
    elif log_type == "System":
        check_system(log_type)
    elif log_type == "All":
        check_application("Application")
        check_security("Security", severity)
        check_system("System")

    continuous()  # Check if to finish program or run continuously.
