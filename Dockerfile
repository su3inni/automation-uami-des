FROM mcr.microsoft.com/azure-functions/python:4-python3.9

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

RUN apt-get update \
    && apt-get install -y \
        wget \
        sudo

COPY requirements.txt /home/site/wwwroot/requirements.txt
RUN pip3 install -r /home/site/wwwroot/requirements.txt

COPY . /home/site/wwwroot
