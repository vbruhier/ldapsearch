# ldapsearch
programme simple de démo pour faire des ldapsearch en java

## commande developper

~~~shell
$ cd <worskpace-projet-ldapsearch>
$ mvn clean package
...
$ 
~~~

## commande utilisateur

~~~shell
$ java -jar target/ldapsearch-jar-with-dependencies.jar -H ldap://ldap.dauphine.fr -D cn=root,dc=dauphine,dc=fr -w password -b dc=dauphine,dc=fr -s base -F ldif
...
$ java -jar target/ldapsearch-jar-with-dependencies.jar -H ldap://ldap.dauphine.fr -D cn=root,dc=dauphine,dc=fr -w password -b dc=dauphine,dc=fr -s base -F json
...
$ 
~~~
