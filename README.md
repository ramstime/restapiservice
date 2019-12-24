# restapiservice
Golang REST API server with Redis database

#compile
go build .

#run
./restapiservice

#test
from browser/postman/curl hit the fallowing urls

POST
http://127.0.0.1:9070/api/companyinfo/v1/comp_instance/cisco-323
GET
http://127.0.0.1:9070/api/companyinfo/v1/all
http://127.0.0.1:9070/api/companyinfo/v1/comp_instance?compid=cisco-323&time=any

