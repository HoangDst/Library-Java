FROM openjdk:21-jdk
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} library-management-system.jar
ENTRYPOINT ["java","-jar","/library-management-system.jar"]
EXPOSE 8080