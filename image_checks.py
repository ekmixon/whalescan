import json
from lib2to3.pgen2.grammar import line

import command
import os
import docker
import pprint
import sys
from docker import APIClient
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    CGREENBG = '\33[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def main(image):
    client = docker.from_env()
    APIClient = docker.APIClient(base_url='')
    pp = pprint.PrettyPrinter(indent=4)
    images = client.images.list()

    def checkDockerHistory(image):

        print("\n[#] Checking for unsafe commands in dockerfile...")
        add_used = 0
        iwr_used = 0
        image_history = image.history()
        image = str(image)
        image = re.findall(r"'(.*?)'", image, re.DOTALL)

        # check if ADD command is used in docker history
        for layer in image_history:
            docker_commands = layer.get('CreatedBy')
            if 'ADD' in docker_commands:
                add_used = 1
            if 'Invoke-WebRequest' in docker_commands:
                if docker_commands.find('Invoke-WebRequest') == -1:
                     iwr_used = 1


        if add_used == 1:
            print(bcolors.WARNING + "Unverified files: Image " + str(image[0]) + " contains ""ADD"" command in docker history, which retrieves and unpacks files from remote URLs. Docker COPY should be used instead."+ bcolors.ENDC)
        if iwr_used == 1:
            print(bcolors.WARNING + "Unverified files: Image " + str(image[0]) + " uses ""Invoke-WebRequest"" to download files without any hash verification. " + bcolors.ENDC)

    def checkImageVersion(image):
        print("\n[#] Checking if latest version of image is used...")

        #Get all commands used in dockerfile
        image_history = image.history()
        for layer in image_history:
            tag = layer.get('Tags')

            #if latest tag is not used
            if str(tag) != 'None':
                if 'latest' not in str(tag):
                    image = str(image)
                    image = re.findall(r"'(.*?)'", image, re.DOTALL)
                    print(bcolors.WARNING + "Cache attack: Image " + str(image[0]) + " is not using the latest tag. This should be used to get the most up to date image. " + bcolors.ENDC)

    checkDockerHistory(image)
    checkImageVersion(image)





