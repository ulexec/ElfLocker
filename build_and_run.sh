docker build -t elflock .
docker run elflock /bin/bash -c "sh docker-entrypoint.sh; /bin/bash"
sudo docker cp $(sudo docker ps -l | awk -F 'elflock' '{print $1}' |  awk -F 'CONTAINER' '{print $1}' | awk -F ' ' '{print $1}'):/elflock/bin/crackme.elflocked .
sudo docker stop $(sudo docker ps -l | awk -F 'elflock' '{print $1}' |  awk -F 'CONTAINER' '{print $1}' | awk -F ' ' '{print $1}')

