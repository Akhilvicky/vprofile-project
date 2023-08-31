from calendar import week
from datetime import datetime, timedelta
import csv
from fileinput import filename
from smtplib import SMTPException
from pingparsing import PingParsing, PingTransmitter
import sys
import paramiko
import re
import json
import os
from urllib import request
from urllib.error import HTTPError
import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     filename="dhc_logs.log"
# )


server_status_table = ''''''
server_status_list = []
server_details_list = []
service_details_list = []
cpu_usage_list = []
mem_usage_list = []
disk_usage_list_all = []
kube_pods_list = []
kube_service_list = []
kube_nodes_list = []
ports_list = []
status_dict = {'red' : 0, 'amber' : 1, 'green' : 2}
kafka_groups = []
kafka_lags = []
kafka_topics = []


def append_to_file(file_name, content):
    try:
        with open(file_name, 'a') as f:
            f.write(content)
    except:
        err_type, value, traceback = sys.exc_info()
        print('{0} at line {1} in {2}'.format(str(value), str(
            traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        return None


def ping_host(host_url: str):
    try:
        logging.info("Pinging the host: "+host_url)
        ping_parser = PingParsing()
        ping_transmitter = PingTransmitter()
        ping_transmitter.destination = host_url
        ping_transmitter.count = 3
        result = ping_transmitter.ping()
        result = ping_parser.parse(result).as_dict()
        logging.info("Ping response: " +
                     (str(result['rtt_avg']) if result['rtt_avg'] else "None"))
        return result['rtt_avg']
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while pinging: "+str(value))
        return None


def get_selinux_status(client: paramiko.SSHClient, root, username):
    try:
        logging.info("Fetching status for Selinux service")
        stdin = None
        stdout = None
        stderr = None

        if username == "root":
            stdin, stdout, stderr = client.exec_command(
                "getenforce")
        else:
            stdin, stdout, stderr = client.exec_command(
                "getenforce")
        err = stderr.read().decode()
        if err:
            logging.error(
                "Error while fetching status for selinux: {0}".format(err))
            return None
        data = stdout.read().decode()
        logging.info("Successfully fetched selinux status")
        return data.strip()
    except:
        err_type, value, traceback = sys.exc_info()

        logging.error(
            "Error while fetching status for Selinux: {0}".format(str(value)))
        return None


def check_url(file_name, urls: list):
    content = ''''''
    url = ''
    try:
        logging.info("Checking for status of the url")
        content = '''    <div class="row">

        <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
            <table class="table table-bordered" style="text-align: center;">
                <thead class="thead-dark">
                    <tr>
                        <th scope="col" colspan="3" style="text-align: center;">
                            <h4>URL Status</h4>
                        </th>
                    </tr>
                </thead>
                <thead class="thead-light">
                    <tr>
                        <th scope="col">URL</th>
                        <th scope="col">Status</th>
                        <th scope="col">Status</th>
                    </tr>
                </thead>
                <tbody>'''
        for url in urls:
            try:
                logging.info("Checking status of: " + url)
                import ssl 
                context = ssl._create_unverified_context()

                status_code = request.urlopen(url, context=context).getcode()
                # print(status_code)
                if status_code != 404 and status_code<500:
                    content += '''<tr>
                                <td>{0}</td>
                                <td>Active</td>
                                <td><span class="green-circle"></span></td>
                            </tr>'''.format(url)

                else:
                    content += '''<tr>
                                <td>{0}</td>
                                <td>Inactive</td>
                                <td><span class="red-circle"></span></td>
                            </tr>'''.format(url)
            except HTTPError :
                content += '''<tr>
                                <td>{0}</td>
                                <td>Active</td>
                                <td><span class="green-circle"></span></td>
                            </tr>'''.format(url)
        content += ''' </tbody>
                </table>
            </div>
        </div>
        <br>
        <hr style="height: 1px; background-color: black;">
        <br>'''

        append_to_file(file_name, content)
        logging.info("Checking of url status completed")        
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Exception while checking the url: "+str(value))
        return None


def connect_windows(host_ip, username, password):
    try:
        logging.info("Connecting to windows machine with ip: " + host_ip)
        from wmi import WMI

        connection = WMI(
            host_ip, user=username, password=password)

        logging.info("Connection successfull")
        return connection
    except Exception as ex:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error occured while connecting to windows machine: "+str(value))
        return None


def connect(host, username, password, os_name):
    try:
        logging.info("Connecting to "+os_name+" machine with IP: "+host)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=username, password=password)
        logging.info("Connection successfull")
        return client
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.info("Error while connecting to linux machine: " + str(value))
        return None

def get_ports_linux(client : paramiko.SSHClient, root):
    try:
        logging.info("Fetching Listening Ports details")
        stdin, stdout, stderr = client.exec_command("echo '{0}'| sudo -S  netstat -tulpn | grep LISTEN".format(root), get_pty=True)
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching Ports Details: "+err)
            return None
        result = stdout.read().decode().strip()

        logging.info("Successfully fetched Listening Ports.")
        return result
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching Listening Ports: "+str(value))

        return None
def get_kube_pods(client: paramiko.SSHClient, root):
    try:
        logging.info("Fetching kubernetes pods details")
        # client.exec_command("echo '{0}'| sudo -S su".format(root))
        stdin, stdout, stderr = client.exec_command(
            "kubectl get pods --all-namespaces | awk 'NR>1'")
        # stdin, stdout, stderr = client.exec_command(
        #     "echo '{0}' | sudo -S kubectl get pods --all-namespaces | awk 'NR>1'".format(root))

        err = stderr.read().decode()
        if err:
            # print("Kube Pods Error->", err)
            logging.error("Error while fetching kubernetes pods: "+err)
            return None
        result = stdout.read().decode().strip().split("\n")
        response = []
        for res in result:
            temp = res.split()
            response.append([temp[0],temp[1], temp[3], temp[5]])
        logging.info("Successfully fetched kubernetes pods.")
        return response
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching kubernetes pods: "+str(value))

        return None


def get_kube_svc(client: paramiko.SSHClient, root):
    try:
        logging.info("Fetching kubernetes services")
        stdin, stdout, stderr = client.exec_command(
            "kubectl get svc --all-namespaces | awk 'NR>1'")
        # stdin, stdout, stderr = client.exec_command(
        #     "echo '{0}' | sudo -S kubectl get svc --all-namespaces | awk 'NR>1'".format(root))

        err = stderr.read().decode()
        if err:
            # print("Kube svc error---->", err)
            logging.error("Error while fetching kubernetes services: "+err)
            return None
        result = stdout.read().decode().strip().split("\n")
        response = []
        for res in result:
            temp = res.split()
            response.append([temp[0],temp[1], temp[3], temp[5], temp[6]])
        logging.info("Successfully fetched kubernetes services")
        return response
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching kubernetes services: "+str(value))

        return None


def get_kube_nodes(client: paramiko.SSHClient, root):
    try:
        logging.info("Fetching kubernetes nodes.")
        stdin, stdout, stderr = client.exec_command(
            "kubectl get nodes | awk 'NR>1'")
        # stdin, stdout, stderr = client.exec_command(
        #     "echo '{0}' | sudo -S kubectl get nodes | awk 'NR>1'".format(root))
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching kubernetes nodes: "+err)
            return None
        result = stdout.read().decode().strip().split("\n")
        response = []
        for res in result:
            temp = res.split()
            response.append([temp[0], temp[1], temp[3]])
        logging.info("Successfully fetched kubernetes nodes.")
        return response
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching kubernetes nodes: "+str(value))

        return None


def update_hostname_ip(file_name, ip, hostname):
    try:
        content = '''<div class = "row" >
            <span class="col-2 col-sm-2 col-xs-2 col-lg-2 col-xl-2"></span>
        <div class = "col-12 col-sm-12 col-xs-12 col-lg-12 col-xl-12" >
                <h4> <b> Host Name  : </b> {0} </h4>
            </div>

        </div >
        <div class = "row" >
        <div class = "col-12 col-sm-12 col-xs-12 col-lg-12 col-xl-12" >
                <h4 > <b>IP Address &nbsp
                : </b> {1} </h4>
            </div>

        </div>
        <br>'''.format(hostname, ip)
        append_to_file(file_name, content)
    except:
        err_type, value, traceback = sys.exc_info()
        print('{0} at line {1} in {2}'.format(str(value), str(
            traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        return None


def get_memory_usage_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching linux memory usage")
        stdin, stdout, stderr = client.exec_command(
            'free -m | awk "NR==2"')
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error("Error while fetching linux memory usage: "+err)
            return None
        # print("Memory Usage ------------>")
        logging.info("Successfully fetched linux memory usage")
        return stdout.read().decode().split()[1:3]
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching linux memory usage: "+str(value))
        return None
    



def update_server_status(file_name, csv_folder, tool):
    try:
        current_time = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
        current_time = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_server_status.csv')
        
        csv_file = open(csv_folder+'/clarios_prod_braio_server_status.csv', 'a', encoding='UTF-8', newline='')
        writer = csv.writer(csv_file)
        server_status_table = '''<div class="row">

            <div class="col-12 col-sm-12 col-md-12 col-lg-12 col-xl-12">
                <table class="table table-bordered" style="text-align: center;">
                    <thead class="thead-dark">
                        <tr>
                            <th colspan="14" scope="col" style="text-align: center;">
                                <h4>Server Status</h4>
                            </th>
                        </tr>
                    </thead>

                    <thead class="thead-light">
                        <tr>
                            <th scope="col">Hostname</th>
                            <th scope="col">Operating System</th>
                            <th scope="col">RAG Status</th>
                            <th scope="col">Ping</th>
                            <th scope="col">Uptime (Days)</th>
                            <th scope="col">Last Boot Time</th>
                            <th scope="col">Utilized CPU (%)</th>
                            <th scope="col">Total Memory (GB)</th>
                            <th scope="col">Utilized Memory (GB)</th>
                            <th scope="col">Total Disk (GB)</th>
                            <th scope="col">Utilized Disk (GB)</th>
                            <th scope="col">Total Services Monitored</th>
                            <th scope="col">Services Running</th>
                            <th scope="col">Services Stopped</th>
                        </tr>
                    </thead>
                    <tbody>'''
        if not is_exist:
            writer.writerow(['Tool','Hostname','Operating System', 'RAG Status', 'Ping', 'Uptime (Days)', 'Last Boot Time', 'Utilized CPU (%)','Total Memory (GB)', 'Utilized Memory (GB)', 'Total Disk (GB)', 'Utilized Disk (GB)', 'Total Services', 'Services Running', 'Services Stopped', "Timestamp"])
        for i in range(len(server_status_list)):
            data = server_status_list[i]
            running = 0
            stopped = 0
            not_found = 0
            total_service = len(service_details_list[i])
            for service in service_details_list[i]:
                if service[1].lower() == "running" or service[2].lower() == "green":
                    running += 1
                elif service[1].lower() == "service not found": 
                    not_found += 1
                else:
                    stopped += 1
            color_list = []
            for i in range(len(data)):
                x = data[i]
                if x is None or x == '-':
                    color_list.append('red')
            if data[11] is not None and data[10] is not None and data[11] != '-' and data[10] != '-':
                perc = (data[11]/data[10])*100
                if perc < 70:
                    color_list.append('green')
                elif perc >= 70 or perc < 90:
                    color_list.append('amber')
                else:
                    color_list.append('red')
            if data[7] is not None and data[7] != '-':
                perc = data[7]
                if perc < 70:
                    color_list.append('green')
                elif perc >= 70 or perc < 90:
                    color_list.append('amber')
                else:
                    color_list.append('red')
            if data[9] is not None and data[8] is not None and data[9] != '-' and data[8] != '-':
                perc = (data[9]/data[8])*100
                if perc < 70:
                    color_list.append('green')
                elif perc >= 70 or perc < 90:
                    color_list.append('amber')
                else:
                    color_list.append('red')
            if running == total_service:
                color_list.append('green')
            else:
                color_list.append('red')

            if 'red' in color_list:
                color = 'red'
            elif 'amber' in color_list:
                color = 'amber'
            else:
                color = 'green'
            server_status_table += '''<tr>
                                        <td> <a href="#{0}">{1}</a></td>
                                        <td>{2}</td>
                                        <td>
                                            <div class="{3}-circle"></div>
                                        </td>
                                        <td>{4}</td>
                                        <td>{5}</td>
                                        <td>{6}</td>
                                        <td>{7}</td>
                                        <td>{8}</td>
                                        <td>{9}</td>
                                        <td>{10}</td>
                                        <td>{11}</td>
                                        <td>{12}</td>
                                        <td>{13}</td>
                                        <td>{14}</td>
                                    </tr>'''.format(data[1], data[0], data[2], color, data[3], '-' if data[4] is None else data[4], '-' if data[5] is None else data[5], '-' if data[7] is None else data[7], data[8], data[9], data[10], data[11], total_service, running, stopped)
            writer.writerow([tool, data[0], data[2], {'red':0,'amber':1,'green':2}[color], data[3], '-' if data[4] is None else data[4],  '-' if data[5] is None else data[5], '-' if data[7] is None else data[7], data[8], data[9], data[10], data[11], total_service, running, stopped, current_time])
        server_status_table += '''</tbody>
                </table>
            </div>
        </div>
        <br>
            <hr style="height: 1px; background-color: black">
    '''

        append_to_file(file_name, server_status_table)
        csv_file.close()
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        return None


# fetch the uptime of the server
def fetch_uptime_windows(connection : paramiko.SSHClient):
    try:
        logging.info("Fetching uptime for windows machine")
        stdin, stdout, stderr = client.exec_command(
            "net statistics workstation    ".format(root))
        err = stderr.read().decode()
        if err:
            # print("Error in last boot ----->", err)
            return None
        output = stdout.read().decode()
        output = re.findall('Statistics .*', output)[1]

        output = output.split()
        output = output[2]+' '+output[3]+' '+output[4]


        stats_date = datetime.strptime(output, '%m/%d/%Y %H:%M:%S %p')

        boot_time = datetime.strftime(stats_date, '%Y-%m-%d %H:%M')
        date_diff = datetime.now()-stats_date
        days_up = date_diff.days
        
        logging.info("Successfully fetched uptime for windows machine")
        return days_up, boot_time
        
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching uptime for windows machine: "+str(value))
        return None


# fetch last boot time
def fetch_last_boot_time_windows(connection):
    try:
        logging.info("Fetching last boot time for windows machine")
        data = connection.Win32_OperatingSystem()
        boot_time = data[0].LastBootUpTime
        boot_time = datetime.strptime(boot_time, "%Y%m%d%H%M%S.%f+%j")
        boot_time = boot_time.strftime("%Y-%m-%d %H:%M")
        logging.info(
            "Successfully fetched last boot time for windows machines")
        return boot_time
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching last boot time for windows machine: "+str(value))
        return None


def fetch_service_status_windows(connection, service_name):
    try:
        logging.info("Fetching status for service: "+service_name)
        if len(service_name) == 0:
            logging.warning("Empty service name.")
            return None
        
        stdin, stdout, stderr = client.exec_command(
            "sc query {0}".format(service_name))
        err = stderr.read().decode()
        if err:
            # print("Error in while  ----->", err)
            logging.error("Error while fetching status for {0}: {1}".format(
                    service_name, err))
            return None
        
        output = stdout.read().decode().strip()
        output = re.findall('STATE .* :.*', output)[0]
        output = re.sub('.*:','',output)
        output = re.sub('[0-9]*', '', output.strip()).strip()
        
        return output
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching status for {0}: {1}".format(
            service_name, str(value)))
        return None


def get_last_boot_linux(client: paramiko.SSHClient, root):
    try:
        logging.info("Fetching last boot time for linux")
        stdin, stdout, stderr = client.exec_command(
            "who -b".format(root))
        err = stderr.read().decode()
        if err:
            # print("Error in last boot ----->", err)
            return None
        result = stdout.read().decode().split(" ")
        length = len(result)
        result = result[length-2]+" "+result[length-1]
        logging.info("Successfully fetched last boot time for linux")
        return result
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching last boot time for linux machine: "+str(value))
        return None


def get_uptime_linux(client: paramiko.SSHClient, root):
    try:
        logging.info("Fetching last boot time for linux machine")
        stdin, stdout, stderr = client.exec_command(
            "uptime -p".format(root))
        err = stderr.read().decode()
        if err:
            # print("Error in uptime ----->", err)
            return None
        result = stdout.read().decode()
        week_index = result.find('week')
        day_index = result.find('day')
        hour_index = result.find('hour')
        min_index = result.find('minute')
        sec_index = result.find('second')
        result = re.compile('[0-9]+').findall(result)
        index = 0
        ans = 0
        if week_index != -1:
            ans += int(result[index])*7
            index += 1
        if day_index != -1:
            ans += int(result[index])
            index += 1
        if hour_index != -1:
            ans += int(result[index])/24
            index += 1
        if min_index != -1:
            ans += int(result[index])/(24*60)
            index += 1
        if sec_index != -1:
            ans += int(result[index])/(24*60*60)
        logging.info("Successfully fetched last boot time for linux.")
        return round(ans, 2)
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching last boot time for linux machine: "+str(value))
        return None


def decrypt_password(key, message):
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


def get_service_status_linux(client: paramiko.SSHClient, service_name, root):
    try:
        logging.info("Fetching status for service: "+service_name)
        if len(service_name) == 0:
            logging.warning("Empty service name.")
            return None
        stdin, stdout, stderr = client.exec_command(
            "systemctl status {0}".format(service_name))
        err = stderr.read().decode()
        if err:
            stdin, stdout, stderr = client.exec_command("ps -ef")
            err = stderr.read().decode()
            if err:
                logging.error("Error while fetching status for {0}: {1}".format(
                    service_name, err))
                return None
            result = stdout.read().decode()
            result = re.findall("{0}".format(service_name), result)
            if len(result)>0:
                return 'running'
            return "stopped"
        data = stdout.read().decode()
        result = re.compile("active \(.*\)").findall(data)
        status = result[0].replace("(", "").replace(")", "").split(" ")[1]
        return status
    except:
        err_type, value, traceback = sys.exc_info()

        logging.error("Error while fetching status for {0}: {1}".format(
            service_name, str(value)))
        return None


def get_cpu_usage_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching cpu usage from linux.")
        stdin, stdout, stderr = client.exec_command(
            'mpstat -P ALL | awk "NR==4"')
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching cpu usage of linux: "+err)
            # print(err)
            return None
        # print("CPU Usage ------------")
        data = stdout.read().decode().split()
        # print("CPU Usgae--->", data)
        if "all" == data[2] or "ALL" == data[2]:
            return data[3:12]
        logging.info("Successfully fetched cpu usage of linux")
        return data[2:11]
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching cpu usage of linux: "+str(value))
        return None


def get_memory_usage_list_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching memory usage contributors for linux")
        stdin, stdout, stderr = client.exec_command(
            'ps -eo cmd,%mem --sort=-%mem | awk "NR>1 && NR<=6"')
        err = stderr.read().decode()
        if err:
            logging.error(
                "Error while fetching memory usage contributors for linux: "+err)
            # print("Error ", err)
            return
        # print("Memory Usage------------->")
        result = stdout.read().decode().strip().split("\n")
        response = []
        for res in result:
            temp = res.split()
            name = ''
            total = len(temp)
            for i in range(total-1):
                name += " "+temp[i]
            response.append([name, float(temp[total-1])])
        logging.info(
            "Successfully fetched memory usage contributors for linux.")
        return response
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching memory usage contributors for linux: "+str(value))
        return None

# fetch the list of processes utilizing cpu


def fetch_cpu_utilized_list_windows(client : paramiko.SSHClient):
    try:
        logging.info("Fetching cpu usage contributors for windos")
        stdin, stdout, stderr = client.exec_command('wmic cpu get loadpercentage')
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching cpu usage of windows :"+err)
            return None
        
        total_usage = stdout.read().decode().split("\n")[1]
        
        
        logging.info("Successfully fetched cpu usage contributors for windows")
        return total_usage, None
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching cpu usage contributors for windows: "+str(value))
        return None

# fetch the list of memory usage


def fetch_memory_usage_windows(client: paramiko.SSHClient, total_memory):
    try:
        logging.info("Fetching memory usage for windows")

        stdin, stdout, stderr = client.exec_command(
            'tasklist')
        err = stderr.read().decode()
        if err:
            logging.error(
                "Error while fetching memory usage contributors for windows: "+err)
            # print("Error ", err)
            return
        output = stdout.read().decode().strip()
        
        output = output.split('\n')[3::]
        response = []
        for x in output:
            temp = x.split()
            n = len(temp)
            if n==0:
                continue
            
            process_name = ' '.join(temp[0:n-5])
            usage = int(temp[n-2].replace(',',''))
            response.append([process_name, round((usage/total_memory)*100, 3)])
        response.sort(key=lambda x : x[1], reverse=True)

        n = len(response)
        logging.info("Successfully fetched memory usage for windows")
        return response[0:min(n,5)]

    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching memory usage for windows: "+str(value))
        return None


def get_os_version_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching linux os version")
        stdin, stdout, stderr = client.exec_command("hostnamectl")
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching linux os version: "+err)
            return None
        result = stdout.read().decode()
        result = re.compile("Operating System: .*").findall(result)
        logging.info("Successfully fetched os version for linux")
        if len(result)>0:
            result = result[0].split(":")
        else:
            return None
        return result[1]
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching os version for linux: "+str(value))
        return None


def generate_table(file_name, csv_folder):
    try:
        logging.info("Generating final HTML Report")
        current_time = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
        current_time = datetime.strptime(current_time, "%Y-%m-%d %H:%M:%S")
        content = ''''''
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_service_status.csv')
        service_csv = open(csv_folder+'/clarios_prod_braio_service_status.csv', 'a', encoding='UTF-8', newline='')
        service_writer = csv.writer(service_csv)
        if not is_exist:
            service_writer.writerow(['Hostname', 'Status', 'Service Name', 'State', 'Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_cpu_utilization.csv')
        cpu_utilization_csv = open(csv_folder+'/clarios_prod_braio_cpu_utilization.csv', 'a', encoding='UTF-8', newline='')
        cpu_writer = csv.writer(cpu_utilization_csv)
        if not is_exist:
            cpu_writer.writerow(['Hostname', 'RAG Status', 'Process Name', '% Utilization','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_memory_utilization.csv')
        memory_utilization_csv = open(csv_folder+'/clarios_prod_braio_memory_utilization.csv', 'a', encoding='UTF-8', newline='')
        memory_writer = csv.writer(memory_utilization_csv)
        if not is_exist:
            memory_writer.writerow(['Hostname', 'RAG Status', 'Process Name', '% Utilization','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_disk_utilization.csv')
        disk_utilization_csv = open(csv_folder+'/clarios_prod_braio_disk_utilization.csv', 'a', encoding='UTF-8', newline='')
        disk_writer = csv.writer(disk_utilization_csv)
        if not is_exist:
            disk_writer.writerow(['Hostname', 'RAG Status', 'Name','Total Space (GB)', 'Utilized Space (GB)','Timestamp'])

        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_ports_status.csv')
        ports_csv = open(csv_folder+'/clarios_prod_braio_ports_status.csv', 'a', encoding='UTF-8', newline='')
        port_writer = csv.writer(ports_csv)
        if not is_exist:
            port_writer.writerow(['Hostname', 'RAG Status', 'Port Number', 'Status','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kube_pods.csv')
        kube_pods_csv = open(csv_folder+'/clarios_prod_braio_kube_pods.csv', 'a', encoding='UTF-8', newline='')
        pods_writer = csv.writer(kube_pods_csv)
        if not is_exist:
            pods_writer.writerow(['Hostname', 'RAG Status', 'Namespace', 'Name', 'Status', 'Age','Timestamp'])
        
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kube_svc.csv')
        kube_svc_csv = open(csv_folder+'/clarios_prod_braio_kube_svc.csv', 'a', encoding='UTF-8', newline='')
        svc_writer = csv.writer(kube_svc_csv)
        if not is_exist:
            svc_writer.writerow(['Hostname', 'Namespace', 'Name', 'Cluster-IP', 'Port', 'Age','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kube_nods.csv')
        kube_nods_csv = open(csv_folder+'/clarios_prod_braio_kube_nods.csv', 'a', encoding='UTF-8', newline='')
        nods_writer = csv.writer(kube_nods_csv)
        if not is_exist:
            nods_writer.writerow(['Hostname', 'RAG Status', 'Name', 'Status', 'Age','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kafka_groups.csv')
        kafka_group_csv = open(csv_folder+'/clarios_prod_braio_kafka_groups.csv', 'a', encoding='UTF-8', newline='')
        group_writer = csv.writer(kafka_group_csv)
        if not is_exist:
            group_writer.writerow(['Hostname', 'Group','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kafka_topics.csv')
        kafka_topic_csv = open(csv_folder+'/clarios_prod_braio_kafka_topics.csv', 'a', encoding='UTF-8', newline='')
        topic_writer = csv.writer(kafka_topic_csv)
        if not is_exist:
            topic_writer.writerow(['Hostname', 'Topic','Timestamp'])
        
        is_exist = os.path.isfile(csv_folder+'/clarios_prod_braio_kafka_lags.csv')
        kafka_lag_csv = open(csv_folder+'/clarios_prod_braio_kafka_lags.csv', 'a', encoding='UTF-8', newline='')
        lag_writer = csv.writer(kafka_lag_csv)
        if not is_exist:
            lag_writer.writerow(['Hostname', 'Group', 'Topic', 'Partition', 'Current_Offset', 'Log_end_offset', 'Lag', 'Consumer_id', 'host', 'Client_id','Timestamp'])
        

        for i in range(len(server_details_list)):
            server_detail = server_details_list[i]
            service_detail = service_details_list[i]
            cpu_usage = cpu_usage_list[i]
            mem_usage = mem_usage_list[i]
            disk_usage = disk_usage_list_all[i]
            pod = kube_pods_list[i]
            node = kube_nodes_list[i]
            svc = kube_service_list[i]
            ports = ports_list[i]
            hostname = server_status_list[i][0]
            group = kafka_groups[i]
            topic = kafka_topics[i]
            lag = kafka_lags[i]
            if server_detail[2] == None:
                continue

            content += '''
                        <div id={0}>
                            <br>
                            <div class="row">
                <span class="col-2 col-sm-2 col-xs-2 col-lg-2 col-xl-2"></span>

                                <div class="col-4 col-sm-4 col-xs-4 col-lg-4 col-xl-4">
                                    <h4><b>Host Name :</b> {1}</h4>
                                </div>
                                <div class="col-6 col-sm-6 col-xs-6 col-lg-6 col-xl-6">
                                    <h4><b>IP Address &nbsp;: </b> {2}</h4>
                                </div>
                            </div>
                            <br>
                            '''.format(server_detail[0], server_detail[1], server_detail[0])
            if service_detail is not None and len(service_detail) > 0:
                content += '''<br>
                            <div class="row">
                                <div class="col-12 col-sm-12 col-md-12 col-lg-12 col-xl-12">
                                    <table class="table table-bordered" style="text-align: center;">
                                        <thead class="thead-dark">
                                            <tr>
                                                <th colspan="4" scope="col">
                                                    <h4>Service Status</h4>
                                                </th>
                                            </tr>
                                        </thead>
                                        <thead class="thead-light">
                                            <tr>
                                                <th scope="col">Status</th>
                                                <th scope="col">Service Name</th>
                                                <th scope="col">State</th>
                                            </tr>
                                        </thead>
                                        <tbody>'''
                for service in service_detail:
                    content += '''
                                            <tr>
                                                <td>
                                                    <div class="{0}-circle"></div>
                                                </td>
                                                <td>{1}</td>
                                                <td>{2}</td>
                                            </tr>

                                            '''.format(service[2], service[0], service[1].capitalize())
                    service_writer.writerow([hostname, status_dict[service[2]], service[0], service[1].capitalize(),current_time])
                content += '''
                                        </tbody>
                                    </table>
                                </div>
                            </div>'''
            if (disk_usage is not None and len(disk_usage) > 0) or (mem_usage is not None and len(mem_usage) > 0) or (cpu_usage is not None and len(cpu_usage) > 0):
                
                content += '''<div class="row">
                        <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                            <table class="table table-bordered" style="text-align: center; ">
                                <thead class="thead-dark">
                                    <tr>
                                        <th colspan="4" scope="col">
                                            <h4>Resource Utilization Contributors</h4>
                                        </th>
                                    </tr>
                                </thead>
            '''

            if cpu_usage is not None:
                if len(cpu_usage) > 0:
                    content += '''
                                            <!-- for cpu utilization -->
                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col" colspan="4">
                                                        <h4>CPU Utilization</h4>
                                                    </th>
                                                </tr>
                                            </thead>

                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">#</th>
                                                    <th scope="col">RAG Status</th>
                                                    <th scope="col">Process Name</th>
                                                    <th scope="col">% CPU Utilized</th>

                                                </tr>
                                            </thead>
                                            <tbody>'''
                    
                    for j in range(len(cpu_usage)):

                        name = cpu_usage[j][0]
                        value = cpu_usage[j][1]
                        color = 'red'
                        if value < 70:
                            color = 'green'
                        elif value < 90:
                            color = 'amber'
                        else:
                            color = 'red'

                        content += '''
                                <tr>
                                    <th scope="row">{0}</th>
                                    <th><div class="{1}-circle"></div></th>
                                    <td>{2}</td>
                                    <td>{3}</td>

                                </tr>
                        '''.format((j+1), color, name, value)
                        cpu_writer.writerow([hostname, status_dict[color], name, value, current_time])
                    content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''

            if mem_usage is not None:
                if len(mem_usage) > 0:

                    content += '''
                        <!--for memory utilization -->
                <div class="row">
                <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                    <table class="table table-bordered" style="text-align: center; ">
                        <thead class="thead-light">
                            <tr>
                                <th scope="col" colspan="4">
                                    <h4>Memory Utilization</h4>
                                </th>
                            </tr>
                        </thead>

                        <thead class="thead-light">
                            <tr>
                                <th scope="col">#</th>
                                <th scope="col">RAG Status</th>
                                <th scope="col">Process Name</th>
                                <th scope="col">Memory Utilized (%)</th>

                            </tr>
                        </thead>
                        <tbody>'''
                    # print(mem_usage)
                    for j in range(len(mem_usage)):

                        name = mem_usage[j][0]
                        usage = mem_usage[j][1]
                        color = 'red'
                        if usage < 60:
                            color = 'green'
                        elif usage >= 60 and usage < 75:
                            color = 'amber'

                        content += '''
                            <tr>
                                <th scope="row">{0}</th>
                                <td><div class="{1}-circle"></div></td>
                                <td>{2}</td>
                                <td>{3}</td>
                            </tr>
                            '''.format((j+1), color, name, usage)
                        memory_writer.writerow([hostname, status_dict[color], name, usage, current_time])
                    content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''

            if disk_usage is not None:
                if len(disk_usage) > 0:
                    content += '''
                        <!-- for disk utilization -->
                            <div class="row">
                                <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                    <table class="table table-bordered" style="text-align: center; ">
                                        <thead class="thead-light">
                                            <tr>
                                                <th scope="col" colspan="4">
                                                    <h4>Disk Utilization</h4>
                                                </th>
                                            </tr>
                                        </thead>

                                        <thead class="thead-light">
                                            <tr>
                                                <th scope="col">RAG Status</th>
                                                <th scope="col">Name</th>
                                                <th scope="col">Total Disk Space (GB)</th>
                                                <th scope="col">Utilized Disk Space (GB)</th>

                                            </tr>
                                        </thead>
                                        <tbody>'''
                    for j in range(len(disk_usage)):
                        disk = disk_usage[j]
                        color = 'red'
                        if disk[1] == '-' or disk[1] == 0:
                            color = 'red'
                        else:
                            percent = (disk[2]/disk[1])*100
                            if percent < 70:
                                color = 'green'
                            elif percent >= 70 and percent < 80:
                                color = 'amber'
                            else:
                                color = 'red'
                        content += '''
                            <tr>
                                <td><div class="{0}-circle"></div></td>
                                <td>{1}</td>
                                <td>{2}</td>
                                <td>{3}</td>

                            </tr>'''.format(color, disk[0], disk[1], disk[2])
                        disk_writer.writerow([hostname, status_dict[color], disk[0], disk[1], disk[2], current_time])
            if (disk_usage is not None and len(disk_usage) > 0) or (cpu_usage is not None and len(cpu_usage) > 0) or (mem_usage is not None and len(mem_usage) > 0):
                content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''

            # kube pods
            if pod is not None:
                if len(pod) > 0:
                    content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="5" scope="col">
                                                        <h4>Kubernetes PODs</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">RAG Status</th>
                                                    <th scope="col">Namespace</th>
                                                    <th scope="col">Name</th>
                                                    <th scope="col">Status</th>
                                                    <th scope="col">Age</th>

                                                </tr>
                                            </thead>
                                            <tbody>'''
                    for j in range(len(pod)):
                        namespace = pod[j][0]
                        name = pod[j][1]
                        status = pod[j][2]
                        age = pod[j][3]

                        content += '''
                                <tr>
                                    <td><div class="{4}-circle"></div></td>
                                    <td>{0}</td>
                                    <td>{1}</td>
                                    <td>{2}</td>
                                    <td>{3}</td>

                                </tr>
                        '''.format(namespace, name, status, age, 'green' if (status.lower() == 'running' or status.lower() == "completed") else 'red')
                        pods_writer.writerow([hostname, 2 if (status.lower() == 'running' or status.lower()=='completed') else 0, namespace, name, status, age, current_time])
                    content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''
            # kube services
            if svc is not None:
                if len(svc) > 0:
                    content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="6" scope="col">
                                                        <h4>Kubernetes Services</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">#</th>
                                                    <th scope="col">Namespace</th>
                                                    <th scope="col">Name</th>
                                                    <th scope="col">Cluter-IP</th>
                                                    <th scope="col">Port</th>
                                                    <th scope="col">Age</th>

                                                </tr>
                                            </thead>
                                            <tbody>'''
                    for j in range(len(svc)):
                        namespace = svc[j][0]
                        name = svc[j][1]
                        ip = svc[j][2]
                        port = svc[j][3]
                        age = svc[j][4]

                        content += '''
                                <tr>
                                    <th scope="row">{0}</th>
                                    <td>{5}</td>
                                    <td>{1}</td>
                                    <td>{2}</td>
                                    <td>{3}</td>
                                    <td>{4}</td>

                                </tr>
                        '''.format((j+1), name, ip, port, age, namespace)
                        svc_writer.writerow([hostname, namespace, name, ip, port, age, current_time])
                    content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''
            # kube nodes
            if node is not None:
                if len(node) > 0:
                    content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="4" scope="col">
                                                        <h4>Kubernetes Nodes</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">RAG Status</th>
                                                    <th scope="col">Name</th>
                                                    <th scope="col">Status</th>
                                                    <th scope="col">Age</th>

                                                </tr>
                                            </thead>
                                            <tbody>'''
                    for j in range(len(node)):

                        name = node[j][0]
                        status = node[j][1]
                        age = node[j][2]
                        color = 'red'
                        if status.lower() == 'ready':
                            color = 'green'
                        content += '''
                                <tr>
                                    <td><div class={0}-circle></div></td>
                                    <td>{1}</td>
                                    <td>{2}</td>
                                    <td>{3}</td>

                                </tr>
                        '''.format(color, name, status, age)
                        nods_writer.writerow([hostname, status_dict[color], name, status, age, current_time])
                    content += '''
                        </tbody>
                    </table>
                </div>
            </div>'''
            
            # Ports
            if ports is not None and len(ports)>0:
                content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="3" scope="col">
                                                        <h4>Ports</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">RAG Status</th>
                                                    <th scope="col">Port Number</th>
                                                    <th scope="col">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody>'''
                for j in range(len(ports)):

                    number = ports[j][0]
                    status = ports[j][1]
                    color = 'red'
                    if status.lower() == 'listening':
                        color = 'green'
                    content += '''
                            <tr>
                                <td><div class={0}-circle></div></td>
                                <td>{1}</td>
                                <td>{2}</td>

                            </tr>
                    '''.format(color, number, status)
                    port_writer.writerow([hostname, status_dict[color], number, status,current_time])
                content += '''
                    </tbody>
                </table>
            </div>
        </div>'''
            
            content += '''
            </div>
            <hr style="height: 1px; background-color: black">

            '''
            # Kafka groups
            if group is not None and len(group)>0:
                content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="2" scope="col">
                                                        <h4>Kafka Groups</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">#</th>
                                                    <th scope="col">Group Name</th>
                                                </tr>
                                            </thead>
                                            <tbody>'''
                for j in range(len(group)):

                    name = group[j]
                    content += '''
                            <tr>
                                <td>{0}</td>
                                <td>{1}</td>

                            </tr>
                    '''.format(j+1, name)
                    group_writer.writerow([hostname, name, current_time])
                content += '''
                    </tbody>
                </table>
            </div>
        </div>'''
            
            content += '''
            </div>
            <hr style="height: 1px; background-color: black">

            '''
            # Kafka topics
            if topic is not None and len(topic)>0:
                content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="2" scope="col">
                                                        <h4>Kafka Topics</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">#</th>
                                                    <th scope="col">Topic Name</th>
                                                </tr>
                                            </thead>
                                            <tbody>'''
                for j in range(len(topic)):

                    name = topic[j]
                    content += '''
                            <tr>
                                <td>{0}</td>
                                <td>{1}</td>

                            </tr>
                    '''.format(j+1, name)
                    topic_writer.writerow([hostname, name, current_time])
                content += '''
                    </tbody>
                </table>
            </div>
        </div>'''
            
            content += '''
            </div>
            <hr style="height: 1px; background-color: black">

            '''
            
	    # Kafka lag
            if lag is not None and len(lag)>0:
                content += '''<div class="row">
                                    <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                                        <table class="table table-bordered" style="text-align: center; ">
                                            <thead class="thead-dark">
                                                <tr>
                                                    <th colspan="9" scope="col">
                                                        <h4>Kafka Lags</h4>
                                                    </th>
                                                </tr>
                                            </thead>


                                            <thead class="thead-light">
                                                <tr>
                                                    <th scope="col">Group</th>
                                                    <th scope="col">Topic</th>
                                                    <th scope="col">Partition</th>
                                                    <th scope="col">Current Offset</th>
                                                    <th scope="col">Log End Offset</th>
                                                    <th scope="col">Lag</th>
                                                    <th scope="col">Consumer ID</th>
                                                    <th scope="col">Host</th>
                                                    <th scope="col">Client ID</th>
                                                </tr>
                                            </thead>
                                            <tbody>'''
                for key in lag.keys():
                    group_name = key
                    data = None 
                    try:
                        data = lag[key]
                    except:
                        pass
                    if data is None :
                        continue
                    for i in range(len(data)):
                        d = data[i].split()
                        topic = d[0]
                        partition = d[1]
                        current_offset = d[2]
                        log_end_offset = d[3]
                        lags = d[4]
                        consumer_id =d[5]
                        host = d[6]
                        client_id = d[7]
                        content += '''
                                <tr>
                                    <td>{0}</td>
                                    <td>{1}</td>
                                    <td>{2}</td>
                                    <td>{3}</td>
                                    <td>{4}</td>
                                    <td>{5}</td>
                                    <td>{6}</td>
                                    <td>{7}</td>
                                    <td>{8}</td>

                                </tr>
                        '''.format(group_name, topic, partition, current_offset, log_end_offset, lags,consumer_id, host, client_id)
                        lag_writer.writerow([hostname,group_name, topic, partition, current_offset, log_end_offset, lags, consumer_id, host, client_id,current_time])
                content += '''
                    </tbody>
                </table>
            </div>
        </div>'''
            
            content += '''
            </div>
            <hr style="height: 1px; background-color: black">

            '''
        append_to_file(file_name, content)
        service_csv.close()
        cpu_utilization_csv.close()
        memory_utilization_csv.close()
        disk_utilization_csv.close()
        kube_pods_csv.close()
        kube_nods_csv.close()
        kube_svc_csv.close()
        ports_csv.close()
        kafka_group_csv.close()
        kafka_topic_csv.close()
        kafka_lag_csv.close()
        logging.info("HTML Report generated successfully")
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while generating HTML Report :"+str(value)+" at line: "+str(traceback.tb_lineno))
        return None

# fetch disk usage list


def fetch_disk_usage_list_windows(connection):
    try:
        logging.info("Fetching usage of disk partitions for windows")
        
        stdin, stdout, stderr = connection.exec_command(
            'wmic logicaldisk get deviceid, size,freespace')
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error("Error while fetching disk usage for windows: "+err)
            return None
        output = stdout.read().decode().split("\n")[1::]
        
        response = []
        for x in output:
            n = len(x.strip())
            if n==0:
                continue
            data = x.split()
            device_id = data[0]
            
            total = round(float(data[2])/(1024*1024*1024),2)
            free = round(float(data[1])/(1024*1024*1024), 2)
            
            used = total-free
            response.append([device_id, total, used])
        
    
        logging.info(
            "Successfully fetched usage of disk partitions for windows")
        return response
    except Exception as ex:
        # print(ex)
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching usage of disk partitions for windows: "+str(value))
        return None


def get_disk_usage_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching disk usage for linux")
        stdin, stdout, stderr = client.exec_command(
            'df | awk "NR>1"')
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error("Error while fetching disk usage for linux: "+err)
            return None
        # print("Disk Usage ------------>")
        logging.info("Successfully fetched disk usage for linux")
        return stdout.read().decode().strip().split("\n")
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error("Error while fetching disk usage for linux: "+str(value))
        return None


def get_cpu_usage_list_linux(client: paramiko.SSHClient):
    try:
        logging.info("Fetching cpu usage contributors for linux")
        stdin, stdout, stderr = client.exec_command(
            'ps -eo cmd,%cpu --sort=-%cpu | awk "NR>1 && NR<=6"')
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error(
                "Error while fetching cpu usage contributors for linux: "+err)
            return
        # print("CPU Usage------------->")
        result = stdout.read().decode().strip().split("\n")
        response = []
        for res in result:
            resp = res.split()
            total = len(resp)
            name = ''
            for i in range(total-1):
                name += " "+resp[i]
            response.append([name, float(resp[total-1])])
        # print(response)
        logging.info("Successfully fetched cpu usage contributors for linux")
        return response
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching cpu usage contributors for linux: "+str(value))
        return None


def fetch_os_version_windows(connection):
    try:
        logging.info("Fetching os version for windowos")
        stdin, stdout, stderr = connection.exec_command(
            'systeminfo')
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error(
                "Error while fetching os version for windows: "+err)
            return
        output = stdout.read().decode()
        os_name = re.findall('OS Name:.* ', output)[0]
        os_name = re.sub('.*:', '', os_name).strip()

        memory =  re.findall('Physical Memory:.*', output)
        total_memory = float(re.sub('[A-Za-z,:]', '',memory[0]).strip())
        free_memory = float(re.sub('[A-Za-z,:]', '',memory[1]).strip())

        total_available_mem = round(
            float(total_memory)/(1024), 2)
        total_used = round((total_memory-free_memory)/(1024), 2)
        logging.info("Successfully fetched os version for windows")
        return os_name, total_available_mem, total_used
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching os version for windows: "+str(value))
        return None
    
def get_consumer_groups(path, server, port, client : paramiko.SSHClient ):
    try:
        logging.info("Fetching kafka consumer groups")
        stdin, stdout, stderr = client.exec_command("cd {0}; ./bin/kafka-consumer-groups.sh --bootstrap-server {1}:{2} --list".format(path, server, port))
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error(
                "Error while fetching kafka consumer groups: "+err)
            return None
        result = stdout.read().decode().strip().split("\n")
        return result
        logging.info("Successfully fetched kafka consumer groups")
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching kafka consumer groups: "+str(value))
        return None

def get_kafka_lag(path, server, port, group, client : paramiko.SSHClient):
    try:
        logging.info("Fetching kafka lag for group {0}".format(group))
        stdin, stdout, stderr = client.exec_command("cd {0}; ./bin/kafka-consumer-groups.sh --bootstrap-server {1}:{2} --describe --group {3} | awk 'NR>2'".format(path, server, port, group))
        err = stderr.read().decode()
        if err:
            logging.error("Error while fetching kafka lag for {0}: {1}".format(group, err))
            return None
        result = stdout.read().decode().strip().split("\n")
        return result
        
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching kafka lag for "+group+": "+str(value))
        return None

def get_zookeeper_topics(path, server, port, client : paramiko.SSHClient):
    try:
        logging.info("Fetching kafka zookeeper topics")
        stdin, stdout, stderr = client.exec_command("cd {0}; ./bin/kafka-topics.sh --zookeeper {1}:{2} --list".format(path, server, port))
        err = stderr.read().decode()
        if err:
            # print("Error ", err)
            logging.error(
                "Error while fetching kafka zookeper topics: "+err)
            return None
        result = stdout.read().decode().strip().split("\n")
        logging.info("Successfully fetched kafka zookeper topics")
        return result
    except:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while fetching kafka zookeeper topics: "+str(value))
        return None


def send_mail(filename, csv_folder):
    logging.info("Send generated report through SMTP")
    f = open(filename)
    content = f.read()
    f.close()
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.application import MIMEApplication
    from os.path import basename
    try: 
        msg =MIMEMultipart()
        msg['Subject'] = "Clarios PROD DHC Report"
        csv_files = os.listdir(csv_folder)
        for f in csv_files:
            try:
                part = None
                with open(csv_folder+"/"+f, "rb") as fil:
                    part = MIMEApplication(
                        fil.read(),
                        Name=basename(f)
                    )
                # After the file is closed
                part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
                msg.attach(part)
            except Exception as ex: 
                logging.error("Error in send mail: "+str(ex))
        part = None
        with open(filename, 'rb') as f:
            part = MIMEApplication(f.read(),
                                   Name=basename(filename))
        part['Content-Disposition'] = 'attachment: filename="%s"' % basename(filename)
        msg.attach(part)
        smtpobj = smtplib.SMTP('smtp.clarios.com')

        cc = ["NAUT-IP-Support@lntinfotech.com", "ace-platformsupport@lntinfotech.com","ace-icc-middleware-support@lntinfotech.com" ,"ravi.deo@lntinfotech.com"]
        to = [""]+cc
        print(cc)
        smtpobj.sendmail("braio.admin-noreply@clarios.com",to ,msg.as_string())
        logging.info("Mail send successfully!!!")
    except SMTPException:
        err_type, value, traceback = sys.exc_info()
        # print('{0} at line {1} in {2}'.format(str(value), str(
        #     traceback.tb_lineno), str(traceback.tb_frame.f_code.co_filename)))
        logging.error(
            "Error while sending mail: "+str(value))
        return None


def clear_csv(folder_path):
    try:
        logging.info("Cleaning older data from csv")
        files = os.listdir(folder_path)
        for f in files:
            file_path = "{0}/{1}".format(folder_path, f)
            header = []
            rows = []
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                count = 0
                for row in reader:
                    count += 1
                    if count == 1:
                        header = row
                        continue
                    if len(row) > 0:
                        rows.append(row)
            filter_date = datetime.now() - timedelta(days=14)
            rows = [row for row in rows if datetime.strptime(
                row[len(row)-1], "%Y-%m-%d %H:%M:%S") >= filter_date]
            with open(file_path, 'w', encoding='UTF-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(header)
                writer.writerows(rows)
    except:
        err_type, value, traceback = sys.exc_info()
        logging.error(
            "Error while clearing CSV: "+str(value))


if __name__ == "__main__":
    home_path = '/home/xbhagatdSA/DHC/DHC_Scripts_and_modules'
    logging.info("DHC Script execution started")
    if not os.path.exists(os.path.join(home_path,"dhc_reports_html")):
        os.makedirs(os.path.join(home_path,"dhc_reports_html"))
    if not os.path.exists(os.path.join(home_path,'dhc_reports_csv')):
        os.makedirs(os.path.join(home_path,'dhc_reports_csv'))
    file_name_format = datetime.strftime(datetime.today(), "%d%m%Y%H%M%S")
    file_name = os.path.join(home_path,'dhc_reports_html/dhc_report_{0}.html').format(
        file_name_format)
    csv_folder =   os.path.join(home_path,'dhc_reports_csv')
    if not os.path.exists(csv_folder):
        os.makedirs(csv_folder)
    clear_csv(csv_folder)
    logging.info("Creating report with name: "+file_name)
    # file_name = "generated_report.html"
    config_file = open(os.path.join(home_path,'config_dhc.json'))
    input_data = json.load(config_file)
    tool = input_data['tool']
    logging.info("Reading server configuration from config_dhc.json")
    header = '''<!DOCTYPE html>
    <html lang="en">

    <head>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
            integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
        <title>Daily Health Check Report</title>
        <style>
            .red-circle {
                width: 25px;
                height: 25px;
                background-color: red;
                border-radius: 50%;
                display: inline-block;
            }

            .amber-circle {
                width: 25px;
                height: 25px;
                background-color: #FFBF00;
                border-radius: 50%;
                display: inline-block;
            }

            .green-circle {
                width: 25px;
                height: 25px;
                background-color: green;
                border-radius: 50%;
                display: inline-block;
            }
            
            table th {
                width: auto !important;
            }
        </style>
    </head>

    <body>

        <div class="row" style="text-align: center; background-color:rgb(40, 117, 143); margin-top:2%">
            <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
                <h2 style="width: 100%; color:white">Daily Health Check Report - '''+tool+'''</h2>
            </div>
        </div>
        <div class="row">
        <div class="col-12 col-sm-12 col-lg-12 col-md-12 col-xl-12">
            <h4 style="text-align: end;">'''+datetime.today().strftime("%d-%m-%Y, %I:%M %p") + '''</h4>
        </div>
        </div>
        <br>


        <div class="row">
            <span class="col-2 col-sm-2 col-lg-2 col-md-2 col-xl-2"></span>
            <div class="col-8 col-sm-8 col-lg-8 col-md-8 col-xl-8">

                <table class="table table-bordered " style="text-align: center; ">
                    <thead class="thead-light">
                        <tr>
                            <th scope="col" colspan="4" style="text-align: center;">Indicators</th>
                        </tr>
                    </thead>
                    <tbody>
                               <tr>
                        <td></td>
                        <td>
                            <div class="green-circle"></div>
                            <!-- <div>Healthy</div> -->
                        </td>
                        <td>
                            <div class="amber-circle"></div>
                            <!-- <div>Warning</div> -->
                        </td>
                        <td>
                            <div class="red-circle"></div>
                            <!-- <div>Critical/Error/Down</div> -->
                        </td>
                    </tr>
                    <tr>
                        <th>Servers/URL</th>
                        <td>Healthy</td>
                        <td>-</td>
                        <td>Critical/Error/Down</td>
                    </tr>
                    <tr>
                        <th>Services/PODs</th>
                        <td>Running</td>
                        <td>-</td>
                        <td>Stopped</td>
                    </tr>
                    <tr>
                        <th>% Utilization (CPU)</th>
                        <td>&lt;70</td>
                        <td>&gt;=70 and &lt;90</td>
                        <td>&gt;=90</td>
                    </tr>
                    <tr>
                        <th>% Utilization (Memory)</th>
                        <td>&lt;60</td>
                        <td>&gt;=60 and &lt;75</td>
                        <td>&gt;=75</td>
                    </tr>
                    <tr>
                        <th>% Utilization (Disk)</th>
                        <td>&lt;70</td>
                        <td>&gt;=70 and &lt;80</td>
                        <td>&gt;=80</td>
                    </tr>

                    </tbody>
                </table>
            </div>
        </div>
        <br>'''.format(tool)

    footer = '''
    </body>

    </html>'''
    


    append_to_file(file_name, header)
    if "urls" in input_data:
        try:
            urls = input_data['urls']
            check_url(file_name, urls)
        except Exception as ex:
            print(str(ex))
    if 'servers' in input_data:
        for server in input_data['servers']:
            try:
                service_details_list.append([])
                cpu_usage_list.append([])
                mem_usage_list.append([])
                disk_usage_list_all.append([])
                kube_pods_list.append([])
                kube_service_list.append([])
                kube_nodes_list.append([])
                ports_list.append([])
                kafka_groups.append([])
                kafka_lags.append({})
                kafka_topics.append([])

                index = len(service_details_list)-1

                result = ping_host(server['server_ip'])
                if result is None:
                    result = 1500
                    # server_status_list.append(
                    #     [server['host_name'], server['server_ip'], server['os_type'], None, '-', '-', 'red', '-', '-', '-', '-', '-'])
                    # continue
                server_details_list.append(
                    [server['server_ip'], server['host_name'], result])

                if server['os_type'].lower() == "windows":
                    password = decrypt_password(
                        server['key'], server['password'])
                    # print(password)
                    connection = connect(
                        server['server_ip'], server['username'], password, server['os_type'])

                    if connection is None:
                        server_status_list.append(
                            [server['host_name'], server['server_ip'], server['os_type'], None, '-', '-', 'red', '-', '-', '-', '-', '-'])

                    else:
                        days_up, boot_time = fetch_uptime_windows(connection)
                        os_version, total_memory, total_mem_usage = fetch_os_version_windows(
                            connection)
                        if os_version is None:
                            os_version = "Windows"

                        mem_usage_list[index] = fetch_memory_usage_windows(
                            connection,total_memory*1024*1024)
                        total_cpu_usage, cpu_usage_list[index] = fetch_cpu_utilized_list_windows(
                            connection)
                        disk_usage_list_all[index] = fetch_disk_usage_list_windows(
                            connection)
                        disk_total = 0
                        disk_usage = 0
                        if disk_usage_list_all[index] is not None:
                            disk_total = 0
                            disk_usage = 0
                            for disk in disk_usage_list_all[index]:
                                disk_total += float(disk[1]
                                                    ) if disk[1] != '-' else 0
                                disk_usage += float(disk[2]
                                                    ) if disk[2] != '-' else 0
                        server_status_list.append([server['host_name'], server['server_ip'], os_version,
                                                   result, days_up, boot_time, 'green' if result <= 500 else 'amber', total_cpu_usage, total_memory, total_mem_usage, round(disk_total, 2), round(disk_usage, 2)])

                        for service in server['service']:
                            if len(service) == 0:
                                continue
                            service_status = fetch_service_status_windows(
                                connection, service)
                            color = 'red'
                            if service_status == None:
                                service_status = "Service Not Found"
                            elif service_status.lower() == 'running':
                                color = 'green'
                            service_details_list[index].append(
                                [service, service_status, color])

                else:
                    password = decrypt_password(
                        server['key'], server['password'])
                    root = decrypt_password(
                        server['root_key'], server['root_password'])
                    client = connect(
                        server['server_ip'], server['username'], password,server['os_type'])
                    if client is None:
                        server_status_list.append(
                            [server['host_name'], server['server_ip'], server['os_type'], None, '-', '-', 'red', '-', '-', '-', '-', '-'])

                    else:

                        days_up = get_uptime_linux(client, None)
                        boot_time = get_last_boot_linux(
                            client, None)

                        os_version = get_os_version_linux(client)
                        if os_version is None:
                            os_version = "Linux"

                        cpu_usage = get_cpu_usage_linux(client)
                        if cpu_usage is not None:
                            cpu_usage = sum([float(i) for i in cpu_usage])
                            cpu_usage = round(cpu_usage, 2)
                        memory_usage = get_memory_usage_linux(client)
                        if memory_usage is None:
                            memory_usage = ['-', '-']
                        else:
                            memory_usage = [round(float(i)/1024, 2)
                                            for i in memory_usage]

                        disk_usage_list = get_disk_usage_linux(client)

                        disk_usage = [0, 0]
                        if disk_usage_list is None:
                            disk_usage = ['-', '-']
                        else:
                            for disk in disk_usage_list:
                                disk_usage[0] += float(disk.split()[1])
                                disk_usage[1] += float(disk.split()[2])
                            disk_usage[0] = round(disk_usage[0]/(1024*1024), 2)
                            disk_usage[1] = round(disk_usage[1]/(1024*1024), 2)

                        server_status_list.append([server['host_name'], server['server_ip'], os_version,
                                                   result, days_up, boot_time, 'green' if result <= 500 else 'amber', cpu_usage, memory_usage[0], memory_usage[1], disk_usage[0], disk_usage[1]])

                        for service in server['service']:
                            if len(service) == 0:
                                continue
                            service_status = get_service_status_linux(
                                client, service, None)
                            color = 'red'
                            if service_status == None:
                                service_status = "Service Not Found"
                            elif service_status.lower() == 'running':
                                color = 'green'
                            service_details_list[index].append(
                                [service, service_status, color])
                            
                        service_status = get_selinux_status(
                            client, root, server['username'])
                        if service_status is None:
                            service_details_list[index].append(
                                ["Selinux", "Not installed", "green"])
                        elif service_status.lower() == "disabled":
                            service_details_list[index].append(
                                ["Selinux", service_status, "green"])
                        else:
                            service_details_list[index].append(
                                ["Selinux", service_status, "red"])

                        cpu_usage_list[index] = get_cpu_usage_list_linux(
                            client)

                        mem_usage_list[index] = get_memory_usage_list_linux(
                            client)
                        other_used = 0
                        other_total = 0
                        if disk_usage_list is None:
                            disk_usage_list_all[index] = None
                        else:
                            for disk in disk_usage_list:
                                d = disk.split()
                                if d[0] == "tmpfs":
                                    other_total += round(
                                        int(d[1])/(1024*1024), 2)
                                    other_used += round(int(d[2]) /
                                                        (1024*1024), 2)
                                else:
                                    disk_usage_list_all[index].append([d[0], round(
                                        int(d[1])/(1024*1024), 2), round(int(d[2])/(1024*1024), 2)])
                            if other_used !=0 or other_total !=0:
                                disk_usage_list_all[index].append(
                                    ["temporary partition", other_total, other_used])
                        kube_nodes_list[index] = get_kube_nodes(client, root)
                        kube_pods_list[index] = get_kube_pods(client, root)
                        kube_service_list[index] = get_kube_svc(client, root)
                        
                        if 'ports' in server.keys():
                            result = get_ports_linux(client, root)
                            if result is not None:
                                for port in server['ports']:
                                    data = re.findall(':{0} '.format(port), result)
                                    if len(data)>0:
                                        ports_list[index].append([port, 'Listening'])
                                    else:
                                        ports_list[index].append([port, 'Not Listening'])

                        if "kafka" in server.keys():
                            kafka = server['kafka']
                            kafka_groups[index] = get_consumer_groups(kafka['path'], kafka['server'], kafka['consumer_port'], client )
                            kafka_topics[index] = get_zookeeper_topics(kafka['path'], kafka['server'], kafka['zookeeper_port'], client)
                            if kafka_groups[index] is not None:
                                for group in kafka_groups[index]:
                                    kafka_lags[index][group] = get_kafka_lag(kafka['path'], kafka['server'], kafka['consumer_port'], group, client)
                                print("Kafka LAGS: "+str(kafka_lags[index]))
                            else:
                                kafka_lags[index] = None
                            
                        
                        
                    if client is not None:
                        client.close()
            except Exception as ex:
                err_type, value, traceback = sys.exc_info()
                logging.error("Error in script: "+str(value))

    update_server_status(file_name, csv_folder, tool)
    generate_table(file_name, csv_folder)
    append_to_file(file_name, footer)
    send_mail(file_name, csv_folder)
