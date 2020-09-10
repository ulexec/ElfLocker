from 32bit/ubuntu:16.04
RUN apt-get update -y
RUN apt-get install dietlibc-dev -y
RUN apt-get install nasm -y 
RUN apt-get install make gcc -y 
RUN apt-get install libcapstone-dev -y
RUN mkdir ./elflock
COPY ./ ./elflock
WORKDIR ./elflock
ENTRYPOINT ["./docker-entrypoint.sh"]
