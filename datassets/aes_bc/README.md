## lib
edit jre\lib\security\java.security
add security.provider.10=org.bouncycastle.jce.provider.BouncyCastleProvider
copy bc*.jar to jre\lib\ext

## cmd
docker build -t aes .
docker run -itd --name aes -v "$PWD":/usr/src/myapp aes /bin/bash
docker exec -it aes javac -cp commons-lang3-3.0.jar Main.java HexUtil.java
docker exec -it aes java -cp commons-lang3-3.0.jar:. Main
