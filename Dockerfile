FROM ubuntu:lts

RUN apt update && apt dist-upgrade -y

COPY ./* /app

VOLUME ./config.yaml /app/config.yaml

WORKDIR /app

RUN pip install -r requirements.txt

RUN chmod +x lws.py && alias lws='python3 ./lws.py'

CMD python3 api.py
