fuser -k 7777/tcp
fuser -k 7778/tcp
fuser -k 7779/tcp
fuser -k 7780/tcp
fuser -k 7781/tcp
fuser -k 7782/tcp
fuser -k 7783/tcp
fuser -k 7784/tcp
fuser -k 7785/tcp
fuser -k 7790/tcp
fuser -k 8888/tcp

kill $(ps aux | grep -w ./Client | grep -v grep | awk '{print $2}')






