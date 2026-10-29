## Revocation Of Token

This project main was to demonstrate the `JWT(JSON Web Token)` token revocation when someone logout so that JWT token get unusable by anybody, to support that i have implemented basic `Social Media Post` demo , in which we can `HTTP POST` and `HTTP GET` thing ,  being the protected endpoints only access by the Authorized JWT TOken , so what happen to this endpoint when i Logout.. This is very important design to protect token from being illicitly which can cause problem .


### WHY WE NEED THIS ?

Suppose we have the logout without the Token Revocation, now JWT expiration has left few time units , if any malicious user get access to that JWT token then boom he/she got the acess to the authorized endpoints.. it could leak good amount of data ..


### HOW THIS WORK ?
We use the Memory based DB(eg: `Redis`) , where we store the Blacklisted JWT  with there JTI as key and token as the value with SET TTL to the remaining_time it have .. 
We Usually checks the JWT Token Validity if it is INVALID or EXPIRED ,  after that Check we must add the revocation token check.. based on that 
we can assure this JWT is revoked then no access.


### Important Details:

PORT:2021
HOSTNAME:localhost

Endpoints
/auth/register
/auth/login
/auth/logout

/{username}/post  POST
/{username}/post?limit=2  GET or /{username}/post?limit=2?next_cursor=eyalkdjlajof.fsafafrwerq

{username} --> it will be specific to the username you have registered 

### USAGE :

For Starting/Initializing..  the stuff:
```bash

docker compose up 

```
or 

```bash
docker compose up --build # for bypassing cache layer..
``` 
After this you can use The curl to test the stuff or use `test.sh` script for the initial test easily..

For Removing Persistent Volumes..
```bash
docker compose down -v
```


