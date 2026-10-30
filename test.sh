#!/bin/bash

set -e

curl  -X POST -H "Content-Type: application/json" -d '{"username":"useNaKe@444","password":"ei0k52o3","email":"NaKe444@his.com"}' "http://localhost:2102/auth/register" >/dev/null 2>&1


TOKEN=$(curl  -X POST -H "Content-Type: application/json" -d '{"username":"useNaKe@444","password":"ei0k52o3"}' "http://localhost:2102/auth/login" | jq -r '.message')


# 1 entering.. 
POSTS=(
    '{"post_title":"how to build http server in asm and c","post_content":"prequisites are the knowledge of the socket programming , i would say that is must ,  not huge depth but at the level you can deal with .. and other is understanding of the asssembly or c nicely .. "}'
    
    '{"post_title":"idempotency in write request","post_content":"why idempotency is best thing to have in the game whent here is request and  dont want to process the request twice and all"}'
    
    '{"post_title":"ai killing cognitive with unethical use","post_content":"we need to make sure this that while using the ai  we should  use and maintian the cognitive skills also , if not then that would be bad for the future..."}'
    
    '{"post_title":"unecessary usage of paid servers for the test","post_content":"most of the test we can do in the local server adn allshit , we can make thing best under less resource constraint then in heavy constraint ,  which can be helpful in the future scenario"}'
    
    '{"post_title":"job market has changed mostly... howt to keep up","post_content":"a person good i nthe linux must  get good depth if he is not getting good offer in the stuff he is doing get the certification add the understanding and then apply for cloud based roles... and same for the other thing in tech role"}'
)


for fruit in "${POSTS[@]}"; do
    # echo "$fruit"
    curl -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "$fruit" \
    "http://localhost:2102/post" >/dev/null 2>&1
done


curl  -X GET -H "Content-Type:application/json" -H "Authorization: Bearer $TOKEN"  "http://localhost:2102/useNaKe@444/post?limit=2" | jq 

echo "Here is the Token (use it for the further requests..): $TOKEN"

echo "DONE..."
