'''
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Saira Hassan, @saiii_h

https://www.github.com/nccgroup/whalescan

Released under Apache license 2.0, see LICENSE for more information

'''



import re
import sys

from time import sleep

import docker
import container_checks
import config_file_checks
import docker_version_checks
import image_checks
import subprocess
import cve_check

client = docker.from_env()
APIClient = docker.APIClient(base_url='')
images = client.images.list()

for count, container in enumerate(client.containers.list(), start=1):
     containerID = container.id[:12]
     print("\n################## Running checks for container " + containerID + " (" + str(count) + "/" + str(len(client.containers.list())) + ") ##################")
     container_checks.main(container)


for count, image in enumerate(images, start=1):
     sleep(2)
     imagestr = str(image)
     imagestr = re.findall(r"'(.*?)'", imagestr, re.DOTALL)
     print("\n################## Running checks for image " + str(imagestr[0]) + " (" + str(count) + "/" + str(len(images)) + ") ##################")
     image_checks.main(image)
     print("\n################## Checking image " + str(imagestr[0]) + " (" + str(count) + "/" + str(len(images)) + ")" + " for vulnerabilities ##################")
     cve_check.main(image)

#Checking docker version and updates
print("\n################## Checking docker version ################## ")
docker_version_checks.main()



#Checking configuration files for vulnerabilities
print("\n################## Checking config files ################## ")
config_file_checks.main()


