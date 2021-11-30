FROM davidcaste/alpine-java-unlimited-jce:jdk

RUN sed -i '/security.provider.9=sun.security.smartcardio.SunPCSC/asecurity.provider.10=org.bouncycastle.jce.provider.BouncyCastleProvider' ${JAVA_HOME}/jre/lib/security/java.security
COPY ${PWD}/bcprov-jdk15on-1.69.jar ${JAVA_HOME}/jre/lib/ext/

WORKDIR /usr/src/myapp
