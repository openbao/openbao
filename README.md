# vault-plugin-database-redis



1.6.0 version of vault needed.


$ vault write database/config/my-redis plugin_name="redis-database-plugin" hosts="localhost" port=6379 username=Administrator password=password allowed_roles=*
Error writing data to database/config/my-redis: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/config/my-redis
Code: 400. Errors:

* error creating database object: Incompatible API version with plugin. Plugin version: 5, Client versions: [3 4]