# KDC Intergation Test Instance for RESDOM.GOKRB5

DO NOT USE THIS CONTAINER FOR ANY PRODUCTION USE!!!

To run:
```bash
docker run -v /etc/localtime:/etc/localtime:ro -p 188:88 -p 188:88/udp --rm --name gokrb5-res jcmturner/gokrb5:kdc-resdom &
```

To build:
```bash
docker build -t jcmturner/gokrb5:kdc-resdom --force-rm=true --rm=true .
docker push jcmturner/gokrb5:kdc-resdom
```


