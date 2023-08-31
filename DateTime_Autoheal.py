from calendar import week
from datetime import datetime, timedelta
import json
import logging
import time
import os
import subprocess
import sys
import paramiko
import pytz

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

local_time_list=[]
universal_time_list=[]
system_clock_sync_list=[]
NTP_service_list=[]
timezone_list=[]

server_ip=[]
username=[]
host_name=[]
password=[]
root_key=[]
root_password=[]
key=[]
is_master=[]

def decrypt_password(message,key):
    try:
        from cryptography.fernet import Fernet
        fernet = Fernet(key.encode())
        data = fernet.decrypt(message.encode())
        return data.decode()
    except:
        err_type, value, traceback = sys.exc_info()
        print('{0} at line {1} in {2}'.format(str(value), str(
            traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        return None
    
def get_timedatectl_output(node,u_name,pass_w):
    # SSH connection setup
    logging.info("Fetching {0} NTP Data".format(node))

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Replace 'admin' with the actual password
    try:
        # Connect to the node
        ssh_client.connect(node,username=u_name,password=pass_w)

        # Execute the timedatectl command
        stdin, stdout, stderr  = ssh_client.exec_command('timedatectl')

        # Read the output
        output = stdout.read().decode().strip()

        # Return the output as a string
        return output
    except:
        err_type, value, traceback = sys.exc_info()
        logging.error("Error fetching {0} NTP Data: ".format(node)+str(value))
    finally:
        # Close the SSH connection
        ssh_client.close()

def NTP_Service_Change(node,u_name,pass_w):
    # SSH connection setup
    logging.info("Setting NTP Service Change active on {0}".format(node))
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Replace 'admin' with the actual password
    # password = 'admin'
   
    try:
        # Connect to the node
        ssh_client.connect(node, username=u_name, password=pass_w)

        # Execute the timedatectl command
        command = f'timedatectl set-ntp true'
        #print(subprocess.run(command, shell=True, input=root_pass, encoding="utf-8"))
        stdin, stdout, stderr = ssh_client.exec_command(command)
        logging.info("Setting NTP Service Change active on {0} ----- Done".format(node))
        # Read the output
        output = stdout.read().decode().strip()
    except:
        err_type, value, traceback = sys.exc_info()
        logging.error("Error activating {0} NTP Service: ".format(node)+str(value))
    finally:
        # Close the SSH connection
        ssh_client.close()
        return 1

def Sync_time(node,u_name,pass_w):
    # SSH connection setup
    logging.info("Synchronizing time on {0}".format(node))
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
   
    try:
        # Connect to the node
        ssh_client.connect(node, username=u_name, password=pass_w)

        #inactive 
        command = f'timedatectl set-ntp false'
        stdin, stdout, stderr = ssh_client.exec_command(command)
        for remaining in range(10, 0, -1):
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} seconds remaining.".format(remaining))
            sys.stdout.flush()
            time.sleep(1)

        sys.stdout.write("\rDeactivated ------ Activating NTP Service ..... Please Wait for Few minutes......!\n")
        #Activate 
        command = f'timedatectl set-ntp true'
        stdin, stdout, stderr = ssh_client.exec_command(command)
        for remaining in range(600, 0, -1):
            sys.stdout.write("\r")
            sys.stdout.write("{:2d} seconds remaining.".format(remaining))
            sys.stdout.flush()
            time.sleep(1)

    except:
        err_type, value, traceback = sys.exc_info()
        logging.error("Error activating {0} NTP Service: ".format(node)+str(value))
    finally:
        # Close the SSH connection
        ssh_client.close()
        logging.info("Synchronizing time on {0} --- done".format(node))
        return 1

def DateTime_Current_timezone(timezone_var):
    try:
        UTC = pytz.utc
        IST = pytz.timezone(timezone_var)
        localtime=datetime.now(IST).strftime('%a %Y-%m-%d %H:%M:%S %Z')
        universaltime=datetime.now(UTC).strftime('%a %Y-%m-%d %H:%M:%S %Z')
        logging.info("NTP Internet Time Fetched successfull : ")
        return localtime,universaltime
    except:
        err_type, value, traceback = sys.exc_info()
        logging.error("Error fetching zone time NTP : "+str(value))
        return "error","error"

if __name__ == "__main__":
    home_path="/home/braio/DHC_Charles_Stanley/"
    config_file = open(home_path+'config_file_autoSync.json')
    input_data = json.load(config_file)
    timezone_var=input_data['timezone']
    IST_local_time,UTC_Time=DateTime_Current_timezone(timezone_var)
    IST_local=IST_local_time.split(":")[0]
    master_sync="no"

    UTC_Time_Master=""
    for servers in input_data:
        for server in input_data['servers']:
            server_ip.append(server['server_ip'])
            username.append(server['username'])
            host_name.append(server['host_name'])
            password.append(server['password'])
            root_password.append(server['root_password'])
            key.append(server['key'])
            root_key.append(server['root_key'])
            is_master.append(server['is_master'])
        break

    for i in range(len(host_name)):
        pass_word=decrypt_password(password[i],key[i])
        output = get_timedatectl_output(host_name[i],username[i],pass_word)
        lines = output.split("\n")
        local_time = lines[0].split(": ")[1]
        universal_time = lines[1].split(": ")[1]
        rtc_time = lines[2].split(": ")[1]
        time_zone = lines[3].split(": ")[1]
        system_clock_sync = lines[5].split(": ")[1]
        ntp_service = lines[4].split(": ")[1]
        rtc_local_tz = lines[6].split(": ")[1]

        local_time_list.append(local_time)
        universal_time_list.append(universal_time)
        system_clock_sync_list.append(system_clock_sync)
        if(ntp_service=="yes"):
            NTP_service_list.append("active")
        else:
            NTP_service_list.append("inactive")
        timezone_list.append(time_zone)
        if(is_master[i]=="Yes"):
            l_time=local_time.split(":")[0]
   
    import csv
    csv_folder_path="/home/braio/DHC_Charles_Stanley/dhc_reports_csv"
    if not os.path.exists(csv_folder_path):
        os.makedirs(csv_folder_path)

    current_time = datetime.now()
    #current_time = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
    is_exist = os.path.isfile(csv_folder_path+ '/TimeSync_status.csv')
    TimeSync_status_csv = open(csv_folder_path+'/TimeSync_status.csv', 'a', encoding='UTF-8', newline='')
    TimeSync_writer = csv.writer(TimeSync_status_csv)
    if not is_exist:
            TimeSync_writer.writerow(['Node', 'Local Time', 'Universal Time', 'System Clock Sync','NTP Service','Time Zone','Timestamp'])
    
    if(l_time==IST_local):
        master_sync="yes"
        logging.info("NTP and Master are in SYNC")
        TimeSync_writer.writerow(["NTP Pool Time",IST_local_time,UTC_Time,"yes","active",timezone_var,current_time])
    else:
        logging.error("NTP and Master are not in  SYNC")
        TimeSync_writer.writerow(["NTP Pool Time",IST_local_time,UTC_Time,"-","-",timezone_var,current_time])

    logging.info("------------------------------Before------------------------------")
    logging.info("Node\tLocal Time\tUniversal Time\tSystem Clock Sync\tNtp Service\tTime Zone")
    for i in range(len(host_name)): 
        logging.info("{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(host_name[i],local_time_list[i],universal_time_list[i],system_clock_sync_list[i],NTP_service_list[i],timezone_list[i]))

    result=0
    for i in range(len(host_name)):
        if(NTP_service_list[i]=="active"):
            logging.info("NTP service active on Node - "+str(host_name[i]))
        else:
            pass_word=decrypt_password(password[i],key[i])
            result = NTP_Service_Change(host_name[i],username[i],pass_word)

    if(result==1):
    #clearing List to Get new data
        local_time_list.clear()
        universal_time_list.clear()
        system_clock_sync_list.clear()
        NTP_service_list.clear()
        timezone_list.clear()
        
        for i in range(len(host_name)):
            pass_word=decrypt_password(password[i],key[i])
            output = get_timedatectl_output(host_name[i],username[i],pass_word)
            lines = output.split("\n")
            local_time = lines[0].split(": ")[1]
            universal_time = lines[1].split(": ")[1]
            rtc_time = lines[2].split(": ")[1]
            time_zone = lines[3].split(": ")[1]
            system_clock_sync = lines[5].split(": ")[1]
            ntp_service = lines[4].split(": ")[1]
            rtc_local_tz = lines[6].split(": ")[1]

            local_time_list.append(local_time)
            universal_time_list.append(universal_time)
            system_clock_sync_list.append(system_clock_sync)
            if(ntp_service=="yes"):
                NTP_service_list.append("active")
            else:
                NTP_service_list.append("inactive")
            timezone_list.append(time_zone)

    result_2=0
    for i in range(len(host_name)):
        if(is_master[i]=="No" and system_clock_sync_list[i]=="yes"):
            logging.info("Time is sync on Node - "+str(host_name[i]))
        elif(is_master[i]=="No" and system_clock_sync_list[i]=="no"):
            pass_word=decrypt_password(password[i],key[i])
            result_2=Sync_time(host_name[i],username[i],pass_word)
        elif(is_master[i]=="Yes" and system_clock_sync_list[i]=="yes"):
            logging.info("Time is sync on Node - "+str(host_name[i]))
        else:
            break

    if(result_2==1):            
    #clearing List to Get new data
        local_time_list.clear()
        universal_time_list.clear()
        system_clock_sync_list.clear()
        NTP_service_list.clear()
        timezone_list.clear()
        
        for i in range(len(host_name)):
            pass_word=decrypt_password(password[i],key[i])
            output = get_timedatectl_output(host_name[i],username[i],pass_word)
            lines = output.split("\n")
            local_time = lines[0].split(": ")[1]
            universal_time = lines[1].split(": ")[1]
            rtc_time = lines[2].split(": ")[1]
            time_zone = lines[3].split(": ")[1]
            system_clock_sync = lines[5].split(": ")[1]
            ntp_service = lines[4].split(": ")[1]
            rtc_local_tz = lines[6].split(": ")[1]

            local_time_list.append(local_time)
            universal_time_list.append(universal_time)
            system_clock_sync_list.append(system_clock_sync)
            if(ntp_service=="yes"):
                NTP_service_list.append("active")
            else:
                NTP_service_list.append("inactive")
            timezone_list.append(time_zone)
    
    logging.info("------------------------------After------------------------------")
    logging.info("Node\tLocal Time\tUniversal Time\tSystem Clock Sync\tNtp Service\tTime Zone")
    for i in range(len(host_name)):
        if(is_master[i]=="Yes"): 
            TimeSync_writer.writerow([host_name[i],local_time_list[i],universal_time_list[i],master_sync,NTP_service_list[i],timezone_list[i],current_time])
        else:
            TimeSync_writer.writerow([host_name[i],local_time_list[i],universal_time_list[i],system_clock_sync_list[i],NTP_service_list[i],timezone_list[i],current_time])

        logging.info("{0}\t{1}\t{2}\t{3}\t{4}\t{5}".format(host_name[i],local_time_list[i],universal_time_list[i],system_clock_sync_list[i],NTP_service_list[i],timezone_list[i]))

    TimeSync_status_csv.close()
        